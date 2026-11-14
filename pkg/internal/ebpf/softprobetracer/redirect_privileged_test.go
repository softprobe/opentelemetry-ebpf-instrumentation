// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package softprobetracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/softprobetracer"

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/softprobe"
)

const helperEnvKey = "SP_BPF_TEST_HELPER_MODE"

type childDialResult struct {
	PeerIP    string `json:"peer_ip"`
	PeerPort  int    `json:"peer_port"`
	LocalPort int    `json:"local_port"`
	Reply     string `json:"reply"`
}

type workerTIDInfo struct {
	Worker int    `json:"worker"`
	TID    uint32 `json:"tid"`
}

func TestHelperChildProcess(_ *testing.T) {
	mode := os.Getenv(helperEnvKey)
	if mode == "" {
		return
	}

	var args []string
	for i, a := range os.Args {
		if a == "--" {
			args = os.Args[i+1:]
			break
		}
	}

	var err error
	switch mode {
	case "outbound-dial":
		err = runHelperOutboundDial(args)
	case "obi-self-in-cgroup":
		err = runHelperOBISelfInCgroup(args)
	case "target-app-server":
		err = runHelperTargetAppServer(args)
	case "external-caller":
		err = runHelperExternalCaller(args)
	case "concurrent-writers":
		err = runHelperConcurrentWriters(args)
	default:
		err = fmt.Errorf("unknown helper mode %q", mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func waitGoSignal() {
	r := bufio.NewReader(os.Stdin)
	_, _ = r.ReadString('\n')
}

func runHelperOutboundDial(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("expected 2 args, got %d", len(args))
	}
	network := args[0]
	target := args[1]

	waitGoSignal()

	var d net.Dialer
	d.Timeout = 5 * time.Second
	var conn net.Conn
	var err error
	if network == "tcp6-v4mapped" {
		ap, parseErr := netip.ParseAddrPort(target)
		if parseErr != nil {
			return fmt.Errorf("parse target: %w", parseErr)
		}
		fd, sockErr := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
		if sockErr != nil {
			return fmt.Errorf("socket6: %w", sockErr)
		}
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0)
		ip4 := ap.Addr().As4()
		var sa6 syscall.SockaddrInet6
		sa6.Port = int(ap.Port())
		sa6.Addr[10] = 0xff
		sa6.Addr[11] = 0xff
		copy(sa6.Addr[12:16], ip4[:])
		if err = syscall.Connect(fd, &sa6); err != nil {
			_ = syscall.Close(fd)
			return fmt.Errorf("connect6 v4mapped: %w", err)
		}
		f := os.NewFile(uintptr(fd), "tcp6-v4mapped")
		conn, err = net.FileConn(f)
		_ = f.Close()
		if err != nil {
			return fmt.Errorf("fileconn: %w", err)
		}
	} else {
		conn, err = d.Dial(network, target)
		if err != nil {
			return fmt.Errorf("dial %s %s: %w", network, target, err)
		}
	}
	defer conn.Close()

	sc, ok := conn.(syscall.Conn)
	if !ok {
		return fmt.Errorf("conn %T does not implement syscall.Conn", conn)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return fmt.Errorf("syscallconn: %w", err)
	}

	var peerIP string
	var peerPort int
	var gpErr error
	_ = rc.Control(func(fd uintptr) {
		sa, e := syscall.Getpeername(int(fd))
		if e != nil {
			gpErr = e
			return
		}
		switch v := sa.(type) {
		case *syscall.SockaddrInet4:
			peerIP = netip.AddrFrom4(v.Addr).String()
			peerPort = v.Port
		case *syscall.SockaddrInet6:
			peerIP = netip.AddrFrom16(v.Addr).Unmap().String()
			peerPort = v.Port
		}
	})
	if gpErr != nil {
		return fmt.Errorf("getpeername: %w", gpErr)
	}

	if _, err = io.WriteString(conn, "ping-outbound\n"); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	localTCP, _ := conn.LocalAddr().(*net.TCPAddr)
	res := childDialResult{
		PeerIP:    peerIP,
		PeerPort:  peerPort,
		LocalPort: localTCP.Port,
		Reply:     strings.TrimSpace(reply),
	}
	return json.NewEncoder(os.Stdout).Encode(res)
}

func runHelperOBISelfInCgroup(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("expected 3 args, got %d", len(args))
	}
	cgroupPath := args[0]
	egressPort, _ := strconv.Atoi(args[1])
	directTarget := args[2]

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("rlimit: %w", err)
	}

	cfg := &obi.Config{}
	cfg.Softprobe = softprobe.Config{
		Enabled:         true,
		EgressProxyPort: egressPort,
	}
	tr := New(cfg, nil, nil)
	defer func() { _ = tr.Close() }()

	if err := tr.LoadStandalone(nil, nil); err != nil {
		return fmt.Errorf("load standalone: %w", err)
	}
	if err := tr.AttachKProbesStandalone(); err != nil {
		return fmt.Errorf("attach kprobes: %w", err)
	}
	if err := tr.AttachCgroup(cgroupPath); err != nil {
		return fmt.Errorf("attach cgroup: %w", err)
	}

	_, _, nsID := currentProcessIdentity()
	tr.AllowPID(app.PID(os.Getpid()), nsID, nil)

	conn, err := net.DialTimeout("tcp4", directTarget, 3*time.Second)
	if err != nil {
		return fmt.Errorf("self dial failed: %w", err)
	}
	defer conn.Close()

	_, _ = io.WriteString(conn, "obi-self-check\n")
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("self read failed: %w", err)
	}
	fmt.Println(strings.TrimSpace(line))
	return nil
}

func runHelperTargetAppServer(args []string) error {
	if len(args) < 1 {
		return errors.New("expected listen addr")
	}
	listenAddr := args[0]

	waitGoSignal()

	ln, err := net.Listen("tcp4", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}
	defer ln.Close()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	fmt.Printf("LISTENING:%d\n", tcpAddr.Port)

	for {
		c, err := ln.Accept()
		if err != nil {
			return nil
		}
		go func(conn net.Conn) {
			defer conn.Close()
			msg, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				return
			}
			_, _ = fmt.Fprintf(conn, "TARGET_APP:%s", msg)
		}(c)
	}
}

func runHelperExternalCaller(args []string) error {
	if len(args) < 1 {
		return errors.New("expected target addr")
	}
	target := args[0]

	waitGoSignal()

	conn, err := net.DialTimeout("tcp4", target, 5*time.Second)
	if err != nil {
		return fmt.Errorf("external dial %s: %w", target, err)
	}
	defer conn.Close()

	if _, err = io.WriteString(conn, "hello-inbound\n"); err != nil {
		return fmt.Errorf("external write: %w", err)
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("external read: %w", err)
	}
	fmt.Println(strings.TrimSpace(reply))
	return nil
}

func runHelperConcurrentWriters(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("expected 3 args, got %d", len(args))
	}
	target := args[0]
	numWorkers, _ := strconv.Atoi(args[1])
	writesPerWorker, _ := strconv.Atoi(args[2])

	stdinReader := bufio.NewReader(os.Stdin)
	_, _ = stdinReader.ReadString('\n')

	conn, err := net.DialTimeout("tcp4", target, 5*time.Second)
	if err != nil {
		return fmt.Errorf("concurrent dial %s: %w", target, err)
	}
	defer conn.Close()

	tids := make([]workerTIDInfo, numWorkers)
	var readyWG sync.WaitGroup
	readyWG.Add(numWorkers)
	startCh := make(chan struct{})
	var doneWG sync.WaitGroup
	doneWG.Add(numWorkers)

	var writeErr atomic.Value

	for w := range numWorkers {
		go func(workerIdx int) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			defer doneWG.Done()

			tid := uint32(unix.Gettid())
			tids[workerIdx] = workerTIDInfo{Worker: workerIdx, TID: tid}
			readyWG.Done()

			<-startCh

			for seq := range writesPerWorker {
				frame := fmt.Sprintf("W=%02d|S=%02d|PAD=%s\n", workerIdx, seq, strings.Repeat("x", (workerIdx%7)+1))
				if _, err := conn.Write([]byte(frame)); err != nil {
					writeErr.Store(err)
					return
				}
			}
		}(w)
	}

	readyWG.Wait()
	if err := json.NewEncoder(os.Stdout).Encode(tids); err != nil {
		return fmt.Errorf("encode tids: %w", err)
	}

	_, _ = stdinReader.ReadString('\n')
	close(startCh)
	doneWG.Wait()

	if v := writeErr.Load(); v != nil {
		return fmt.Errorf("worker write error: %v", v)
	}

	_, _ = bufio.NewReader(conn).ReadString('\n')
	return nil
}

func createIsolatedTestCgroup(t *testing.T) (string, int) {
	t.Helper()

	base := "/sys/fs/cgroup"
	require.True(t, isCgroup2Path(base), "/sys/fs/cgroup must be cgroup v2")

	dir := filepath.Join(base, fmt.Sprintf("sp-obi-test-%d-%d", os.Getpid(), time.Now().UnixNano()))
	require.NoError(t, os.Mkdir(dir, 0o755))

	cgFile, err := os.Open(dir)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = cgFile.Close()
		for range 20 {
			if err := os.Remove(dir); err == nil || os.IsNotExist(err) {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	})

	return dir, int(cgFile.Fd())
}

func spawnHelperInCgroup(t *testing.T, cgFD int, mode string, args ...string) (*exec.Cmd, io.WriteCloser, *bufio.Reader) {
	t.Helper()

	cmdArgs := append([]string{"-test.run=^TestHelperChildProcess$", "--"}, args...)
	cmd := exec.Command(os.Args[0], cmdArgs...)
	cmd.Env = append(os.Environ(), helperEnvKey+"="+mode)
	cmd.Stderr = os.Stderr
	if cgFD >= 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			UseCgroupFD: true,
			CgroupFD:    cgFD,
		}
	}

	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)

	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	return cmd, stdin, bufio.NewReader(stdout)
}

func reserveLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

func monotonicNowNs() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

func TestPrivilegedEBPFRedirectAndWriteCorrelation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root privileges to load and attach cgroup/sk_lookup/kprobe BPF programs")
	}

	require.NoError(t, rlimit.RemoveMemlock())

	cgroupPath, cgFD := createIsolatedTestCgroup(t)

	egressLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer egressLn.Close()
	egressPort := egressLn.Addr().(*net.TCPAddr).Port

	ingressLn, err := ListenIngress(context.Background(), "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer ingressLn.Close()
	ingressPort := ingressLn.Addr().(*net.TCPAddr).Port

	cfg := &obi.Config{}
	cfg.EBPF.MaxTransactionTime = 5 * time.Minute
	cfg.EBPF.CgroupFSPath = cgroupPath
	cfg.Softprobe = softprobe.Config{
		Enabled:          true,
		IngressProxyPort: ingressPort,
		EgressProxyPort:  egressPort,
		BackendURL:       "http://127.0.0.1:18090",
	}

	tracker := softprobe.NewWriteContextTracker(8192, 2*time.Minute)
	tr := New(cfg, nil, nil)
	tr.SetWriteTracker(tracker)
	t.Cleanup(func() { _ = tr.Close() })

	require.NoError(t, tr.LoadStandalone(nil, nil), "BPF programs must pass Linux verifier")
	require.NoError(t, tr.AttachKProbesStandalone())
	require.NoError(t, tr.AttachCgroup(cgroupPath))
	require.NoError(t, tr.AttachNetNS("/proc/self/ns/net"))
	require.NoError(t, tr.RegisterIngressListener(ingressLn))

	runCtx, cancelRun := context.WithCancel(context.Background())
	var runWG sync.WaitGroup
	runWG.Go(func() {
		tr.Run(runCtx, nil, nil)
	})
	t.Cleanup(func() {
		cancelRun()
		runWG.Wait()
	})

	_, _, nsID := currentProcessIdentity()

	t.Run("OutboundRedirectAndGetpeernameIPv4AndIPv6Mapped", func(t *testing.T) {
		type acceptedInfo struct {
			cookie  uint64
			origDst OrigDst
			ok      bool
			err     error
		}

		cases := []struct {
			name    string
			network string
			target  string
			wantIP  string
			wantPrt uint16
		}{
			{
				name:    "ipv4_connect4_and_getpeername4",
				network: "tcp4",
				target:  "198.51.100.42:19443",
				wantIP:  "198.51.100.42",
				wantPrt: 19443,
			},
			{
				name:    "ipv6_v4mapped_connect6_and_getpeername6",
				network: "tcp6-v4mapped",
				target:  "198.51.100.77:29443",
				wantIP:  "198.51.100.77",
				wantPrt: 29443,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				acceptCh := make(chan acceptedInfo, 1)
				go func() {
					c, accErr := egressLn.Accept()
					if accErr != nil {
						acceptCh <- acceptedInfo{err: accErr}
						return
					}
					defer c.Close()

					cookie, origDst, ok := tr.LookupOrigDst(c.RemoteAddr())
					line, rdErr := bufio.NewReader(c).ReadString('\n')
					if rdErr == nil {
						_, _ = fmt.Fprintf(c, "egress-ack:%s", line)
					}
					acceptCh <- acceptedInfo{
						cookie:  cookie,
						origDst: origDst,
						ok:      ok,
						err:     rdErr,
					}
				}()

				cmd, stdin, stdout := spawnHelperInCgroup(t, cgFD, "outbound-dial", tc.network, tc.target)
				childPID := uint32(cmd.Process.Pid)
				tr.AllowPID(app.PID(childPID), nsID, nil)
				defer tr.BlockPID(app.PID(childPID), nsID)

				_, err := io.WriteString(stdin, "GO\n")
				require.NoError(t, err)

				rawOut, err := stdout.ReadString('\n')
				require.NoError(t, err)
				require.NoError(t, cmd.Wait())

				var childRes childDialResult
				require.NoError(t, json.Unmarshal([]byte(rawOut), &childRes))
				assert.Equal(t, tc.wantIP, childRes.PeerIP, "getpeername inside child must return original upstream IP")
				assert.Equal(t, int(tc.wantPrt), childRes.PeerPort, "getpeername inside child must return original upstream port")
				assert.Equal(t, "egress-ack:ping-outbound", childRes.Reply)

				acc := <-acceptCh
				require.NoError(t, acc.err)
				require.True(t, acc.ok, "LookupOrigDst must resolve client_sock_cookie and orig_dst")
				assert.NotZero(t, acc.cookie)
				assert.Equal(t, netip.MustParseAddrPort(fmt.Sprintf("%s:%d", tc.wantIP, tc.wantPrt)), acc.origDst.AddrPort)
				assert.Equal(t, childPID, acc.origDst.PID)
			})
		}
	})

	t.Run("SelfPIDExclusionZeroLoop", func(t *testing.T) {
		directLn, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		defer directLn.Close()

		var directHits atomic.Int32
		go func() {
			for {
				c, accErr := directLn.Accept()
				if accErr != nil {
					return
				}
				directHits.Add(1)
				go func(conn net.Conn) {
					defer conn.Close()
					msg, rdErr := bufio.NewReader(conn).ReadString('\n')
					if rdErr == nil {
						_, _ = fmt.Fprintf(conn, "direct-upstream:%s", msg)
					}
				}(c)
			}
		}()

		tr.AllowPID(app.PID(os.Getpid()), nsID, nil)
		selfConn, err := net.DialTimeout("tcp4", directLn.Addr().String(), 3*time.Second)
		require.NoError(t, err)
		_, err = io.WriteString(selfConn, "parent-obi\n")
		require.NoError(t, err)
		reply, err := bufio.NewReader(selfConn).ReadString('\n')
		require.NoError(t, err)
		_ = selfConn.Close()
		assert.Equal(t, "direct-upstream:parent-obi", strings.TrimSpace(reply))

		selfCgPath, selfCgFD := createIsolatedTestCgroup(t)
		dummyEgressPort := reserveLoopbackPort(t)
		cmd, _, stdout := spawnHelperInCgroup(
			t,
			selfCgFD,
			"obi-self-in-cgroup",
			selfCgPath,
			strconv.Itoa(dummyEgressPort),
			directLn.Addr().String(),
		)
		out, err := stdout.ReadString('\n')
		require.NoError(t, err)
		require.NoError(t, cmd.Wait())
		assert.Equal(t, "direct-upstream:obi-self-check", strings.TrimSpace(out))
		assert.GreaterOrEqual(t, directHits.Load(), int32(2))
	})

	t.Run("InboundInterceptionAndBypassForwarding", func(t *testing.T) {
		srvCmd, srvStdin, srvStdout := spawnHelperInCgroup(t, cgFD, "target-app-server", "127.0.0.1:0")
		srvPID := uint32(srvCmd.Process.Pid)
		tr.AllowPID(app.PID(srvPID), nsID, nil)
		defer tr.BlockPID(app.PID(srvPID), nsID)

		_, err := io.WriteString(srvStdin, "GO\n")
		require.NoError(t, err)

		listenLine, err := srvStdout.ReadString('\n')
		require.NoError(t, err)
		portStr := strings.TrimSpace(strings.TrimPrefix(listenLine, "LISTENING:"))
		appPortInt, err := strconv.Atoi(portStr)
		require.NoError(t, err)
		appPort := uint16(appPortInt)

		relocated, ok := tr.LookupRelocatedPort(appPort)
		require.True(t, ok, "cgroup/post_bind4 must register target app port in sp_app_ports")
		assert.Equal(t, appPort, relocated)

		ingressDone := make(chan struct{})
		defer close(ingressDone)
		go func() {
			for {
				inConn, accErr := ingressLn.Accept()
				if accErr != nil {
					return
				}
				go func(clientConn net.Conn) {
					defer clientConn.Close()
					reqLine, rdErr := bufio.NewReader(clientConn).ReadString('\n')
					if rdErr != nil {
						return
					}
					appConn, dialErr := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", appPort), 3*time.Second)
					if dialErr != nil {
						return
					}
					defer appConn.Close()

					_, _ = io.WriteString(appConn, reqLine)
					appReply, rdErr := bufio.NewReader(appConn).ReadString('\n')
					if rdErr != nil {
						return
					}
					_, _ = fmt.Fprintf(clientConn, "VIA_OBI_INGRESS->%s", appReply)
				}(inConn)
			}
		}()

		callerCmd, callerStdin, callerStdout := spawnHelperInCgroup(
			t,
			-1,
			"external-caller",
			fmt.Sprintf("127.0.0.1:%d", appPort),
		)
		_, err = io.WriteString(callerStdin, "GO\n")
		require.NoError(t, err)

		callerReply, err := callerStdout.ReadString('\n')
		require.NoError(t, err)
		require.NoError(t, callerCmd.Wait())
		assert.Equal(t, "VIA_OBI_INGRESS->TARGET_APP:hello-inbound", strings.TrimSpace(callerReply))
	})

	t.Run("Concurrent20GoroutinesLocklessWriteOffsetTraceCorrelation", func(t *testing.T) {
		const (
			numWorkers      = 20
			writesPerWorker = 5
			totalFrames     = numWorkers * writesPerWorker
		)

		type capturedStream struct {
			cookie uint64
			orig   OrigDst
			ok     bool
			data   []byte
			err    error
		}
		streamCh := make(chan capturedStream, 1)

		go func() {
			c, accErr := egressLn.Accept()
			if accErr != nil {
				streamCh <- capturedStream{err: accErr}
				return
			}
			defer c.Close()

			cookie, orig, ok := tr.LookupOrigDst(c.RemoteAddr())
			reader := bufio.NewReader(c)
			var buf []byte
			for range totalFrames {
				line, rdErr := reader.ReadBytes('\n')
				if rdErr != nil {
					streamCh <- capturedStream{cookie: cookie, orig: orig, ok: ok, data: buf, err: rdErr}
					return
				}
				buf = append(buf, line...)
			}
			_, _ = io.WriteString(c, "DONE\n")
			streamCh <- capturedStream{cookie: cookie, orig: orig, ok: ok, data: buf}
		}()

		cmd, stdin, stdout := spawnHelperInCgroup(
			t,
			cgFD,
			"concurrent-writers",
			"198.51.100.200:39443",
			strconv.Itoa(numWorkers),
			strconv.Itoa(writesPerWorker),
		)
		childPID := uint32(cmd.Process.Pid)
		tr.AllowPID(app.PID(childPID), nsID, nil)
		defer tr.BlockPID(app.PID(childPID), nsID)

		_, err := io.WriteString(stdin, "DIAL\n")
		require.NoError(t, err)

		tidLine, err := stdout.ReadBytes('\n')
		require.NoError(t, err)
		var workers []workerTIDInfo
		require.NoError(t, json.Unmarshal(tidLine, &workers))
		require.Len(t, workers, numWorkers)

		wantTraceByWorker := make(map[int][16]byte, numWorkers)
		wantSpanByWorker := make(map[int][8]byte, numWorkers)
		nowNs := monotonicNowNs()

		for _, w := range workers {
			var traceID [16]byte
			traceID[0] = 0x5a
			traceID[1] = byte(w.Worker + 1)
			traceID[15] = byte(0xa0 + w.Worker)

			var spanID [8]byte
			spanID[0] = 0x7b
			spanID[7] = byte(w.Worker + 1)

			wantTraceByWorker[w.Worker] = traceID
			wantSpanByWorker[w.Worker] = spanID

			tkey := BpfTraceKeyT{
				ExtraId: 0,
				P_key: BpfPidKeyT{
					Tid: w.TID,
					Pid: childPID,
					Ns:  nsID,
				},
			}
			tpVal := BpfTpInfoPidT{
				Tp: BpfTpInfoT{
					TraceId: traceID,
					SpanId:  spanID,
					Ts:      nowNs,
					Flags:   1,
				},
				Pid:   childPID,
				Valid: 1,
			}
			require.NoError(t, tr.bpfObjects.ServerTraces.Update(&tkey, &tpVal, 0))
			defer func(k BpfTraceKeyT) {
				_ = tr.bpfObjects.ServerTraces.Delete(&k)
			}(tkey)
		}

		_, err = io.WriteString(stdin, "WRITE\n")
		require.NoError(t, err)

		stream := <-streamCh
		require.NoError(t, stream.err)
		require.True(t, stream.ok)
		require.NotZero(t, stream.cookie)
		assert.Equal(t, netip.MustParseAddrPort("198.51.100.200:39443"), stream.orig.AddrPort)
		require.NoError(t, cmd.Wait())

		require.Eventually(t, func() bool {
			var probeOffset uint64
			remaining := stream.data
			for len(remaining) > 0 {
				idx := strings.IndexByte(string(remaining), '\n')
				if idx < 0 {
					break
				}
				if _, found := tracker.LookupExact(stream.cookie, probeOffset); !found {
					return false
				}
				probeOffset += uint64(idx + 1)
				remaining = remaining[idx+1:]
			}
			return probeOffset == uint64(len(stream.data))
		}, 3*time.Second, 10*time.Millisecond, "all 100 concurrent writes must be recorded in WriteContextTracker")

		var offset uint64
		lines := strings.Split(strings.TrimSuffix(string(stream.data), "\n"), "\n")
		require.Len(t, lines, totalFrames)

		for i, line := range lines {
			frameLen := uint32(len(line) + 1)
			var workerIdx int
			var seq int
			var pad string
			_, scanErr := fmt.Sscanf(line, "W=%02d|S=%02d|PAD=%s", &workerIdx, &seq, &pad)
			require.NoErrorf(t, scanErr, "malformed frame %d: %q", i, line)

			wctx, found := tracker.LookupExact(stream.cookie, offset)
			require.Truef(t, found, "missing WriteContextTracker entry at cookie=%d offset=%d", stream.cookie, offset)
			assert.Equalf(t, frameLen, wctx.PayloadLen, "payload length mismatch at offset=%d", offset)
			wantTrace := wantTraceByWorker[workerIdx]
			wantSpan := wantSpanByWorker[workerIdx]
			assert.Equalf(
				t,
				hex.EncodeToString(wantTrace[:]),
				hex.EncodeToString(wctx.TraceID[:]),
				"frame %d (worker=%d, offset=%d) resolved wrong trace_id",
				i,
				workerIdx,
				offset,
			)
			assert.Equalf(
				t,
				hex.EncodeToString(wantSpan[:]),
				hex.EncodeToString(wctx.ServerSpanID[:]),
				"frame %d (worker=%d, offset=%d) resolved wrong span_id",
				i,
				workerIdx,
				offset,
			)

			// LookupAtOffset scans WriteContextTracker's 64-entry per-socket ring, so only the last 64 writes stay range-indexable.
			if i >= totalFrames-64 {
				midCtx, midFound := tracker.LookupAtOffset(stream.cookie, offset+uint64(frameLen/2))
				require.True(t, midFound)
				assert.Equal(t, wantTrace, midCtx.TraceID)
			}

			offset += uint64(frameLen)
		}
	})
}
