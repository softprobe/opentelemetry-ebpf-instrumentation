// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	maxDatabaseFrameBytes   = 16 << 20
	postgresReadyForQuery   = byte('Z')
	postgresQuery           = byte('Q')
	postgresTerminate       = byte('X')
	postgresSSLRequest      = uint32(80877103)
	postgresGSSRequest      = uint32(80877104)
	mysqlInitDB             = byte(0x02)
	mysqlQuery              = byte(0x03)
	mysqlSetOption          = byte(0x1b)
	mysqlResetConnection    = byte(0x1f)
	mysqlPing               = byte(0x0e)
	mysqlQuit               = byte(0x01)
	mysqlClientQueryAttrs   = uint32(1 << 27)
	mysqlClientDeprecateEOF = uint32(1 << 24)
)

type DatabaseListenerConfig struct {
	Listen       string
	Upstream     string
	DatabaseName string
}

type DatabaseProxyConfig struct {
	Postgres          DatabaseListenerConfig
	MySQL             DatabaseListenerConfig
	RequestContextMap RequestTraceContextReader
	Gateway           *Gateway
}

type DatabaseProxy struct {
	config DatabaseProxyConfig
}

func NewDatabaseProxy(cfg DatabaseProxyConfig) (*DatabaseProxy, error) {
	if cfg.Gateway == nil {
		return nil, errors.New("database proxy requires a Softprobe gateway")
	}
	for name, listener := range map[string]DatabaseListenerConfig{
		"PostgreSQL": cfg.Postgres,
		"MySQL":      cfg.MySQL,
	} {
		if listener.Listen == "" {
			if listener.Upstream != "" {
				return nil, fmt.Errorf("%s upstream requires a listen address", name)
			}
			continue
		}
		if listener.Upstream == "" {
			return nil, fmt.Errorf("%s listener requires an upstream address", name)
		}
	}
	if cfg.Gateway.mode == ReplayMode && cfg.RequestContextMap == nil &&
		(cfg.Postgres.Listen != "" || cfg.MySQL.Listen != "") {
		return nil, errors.New("database replay requires OBI's per-request context map")
	}
	return &DatabaseProxy{config: cfg}, nil
}

// Listen serves the configured database listeners until the context is
// cancelled. Record mode is a transparent TCP forwarder; OBI captures the
// protocol payloads on the client connection. Replay mode terminates each
// supported query locally and writes the recorded protocol response frames.
func (p *DatabaseProxy) Listen(ctx context.Context) error {
	type listenerEndpoint struct {
		config   DatabaseListenerConfig
		protocol string
	}
	endpoints := make([]listenerEndpoint, 0, 2)
	if p.config.Postgres.Listen != "" {
		endpoints = append(endpoints, listenerEndpoint{config: p.config.Postgres, protocol: "postgresql"})
	}
	if p.config.MySQL.Listen != "" {
		endpoints = append(endpoints, listenerEndpoint{config: p.config.MySQL, protocol: "mysql"})
	}
	listeners := make([]net.Listener, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.config.Listen == "" {
			continue
		}
		listener, err := net.Listen("tcp", endpoint.config.Listen)
		if err != nil {
			for _, opened := range listeners {
				_ = opened.Close()
			}
			return fmt.Errorf("listen for database proxy: %w", err)
		}
		listeners = append(listeners, listener)
	}
	if len(listeners) == 0 {
		return nil
	}
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()

	var wg sync.WaitGroup
	for i, listener := range listeners {
		entry := endpoints[i]
		wg.Add(1)
		go func(listener net.Listener, endpoint listenerEndpoint) {
			defer wg.Done()
			for {
				conn, err := listener.Accept()
				if err != nil {
					if ctx.Err() == nil {
						slog.Error("database proxy accept failed", "protocol", endpoint.protocol, "error", err)
					}
					return
				}
				go p.serveConnection(ctx, conn, endpoint.config, endpoint.protocol)
			}
		}(listener, entry)
	}
	<-ctx.Done()
	for _, listener := range listeners {
		_ = listener.Close()
	}
	wg.Wait()
	return nil
}

func (p *DatabaseProxy) serveConnection(ctx context.Context, client net.Conn, cfg DatabaseListenerConfig, protocol string) {
	defer client.Close()
	upstream, err := net.DialTimeout("tcp", cfg.Upstream, 5*time.Second)
	if err != nil {
		slog.Warn("database upstream connect failed", "protocol", protocol, "error", err)
		return
	}
	defer upstream.Close()

	if p.config.Gateway.mode == RecordMode {
		proxyTCP(ctx, client, upstream)
		return
	}

	if protocol == "postgresql" {
		err = p.servePostgresReplay(client, upstream, cfg)
	} else {
		err = p.serveMySQLReplay(client, upstream, cfg)
	}
	if err != nil && ctx.Err() == nil {
		slog.Warn("database replay connection failed", "protocol", protocol, "error", err)
	}
}

func proxyTCP(ctx context.Context, client, upstream net.Conn) {
	finished := make(chan struct{}, 2)
	copyDirection := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tcp, ok := dst.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		finished <- struct{}{}
	}
	go copyDirection(upstream, client)
	go copyDirection(client, upstream)
	select {
	case <-ctx.Done():
	case <-finished:
		_ = client.SetDeadline(time.Now().Add(100 * time.Millisecond))
		_ = upstream.SetDeadline(time.Now().Add(100 * time.Millisecond))
		<-finished
	}
}

func (p *DatabaseProxy) servePostgresReplay(client, upstream net.Conn, cfg DatabaseListenerConfig) error {
	startup, sslRequested, err := readPostgresStartup(client)
	if err != nil {
		return err
	}
	if sslRequested {
		_, _ = client.Write([]byte{'N'})
		startup, _, err = readPostgresStartup(client)
		if err != nil {
			return err
		}
	}
	if _, err := upstream.Write(startup); err != nil {
		return err
	}
	if err := relayPostgresStartup(client, upstream); err != nil {
		return err
	}

	reader := bufio.NewReader(client)
	for {
		message, err := readPostgresMessage(reader)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if len(message) == 0 {
			continue
		}
		switch message[0] {
		case postgresTerminate:
			return nil
		case postgresQuery:
			sql, err := postgresQueryText(message)
			if err != nil {
				return err
			}
			if isReplaySessionCommand("postgresql", sql) {
				if err := p.discardRequestContext(client.RemoteAddr()); err != nil {
					return err
				}
				if err := relayPostgresSessionQuery(client, upstream, message); err != nil {
					return err
				}
				continue
			}
			response, err := p.queryResponse(client.RemoteAddr(), cfg.DatabaseName, "postgresql", sql)
			if err != nil {
				return err
			}
			if _, err := client.Write(response); err != nil {
				return err
			}
		default:
			return fmt.Errorf("PostgreSQL replay supports simple-query messages only (received %q)", message[0])
		}
	}
}

func readPostgresStartup(reader io.Reader) ([]byte, bool, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, false, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length < 8 || length > maxDatabaseFrameBytes {
		return nil, false, fmt.Errorf("invalid PostgreSQL startup length %d", length)
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, false, err
	}
	message := append(header[:], body...)
	code := binary.BigEndian.Uint32(body[:4])
	return message, code == postgresSSLRequest || code == postgresGSSRequest, nil
}

func relayPostgresStartup(client, upstream net.Conn) error {
	reader := bufio.NewReader(upstream)
	for {
		message, err := readPostgresMessage(reader)
		if err != nil {
			return err
		}
		if len(message) == 0 {
			return errors.New("empty PostgreSQL startup response")
		}
		if message[0] == 'R' && (len(message) < 9 || binary.BigEndian.Uint32(message[5:9]) != 0) {
			return errors.New("PostgreSQL replay requires trust authentication")
		}
		if _, err := client.Write(message); err != nil {
			return err
		}
		if message[0] == postgresReadyForQuery {
			return nil
		}
	}
}

func readPostgresMessage(reader io.Reader) ([]byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[1:])
	if length < 4 || length > maxDatabaseFrameBytes {
		return nil, fmt.Errorf("invalid PostgreSQL message length %d", length)
	}
	message := make([]byte, 1+length)
	copy(message, header[:])
	if _, err := io.ReadFull(reader, message[len(header):]); err != nil {
		return nil, err
	}
	return message, nil
}

func postgresQueryText(message []byte) (string, error) {
	if len(message) < 6 {
		return "", errors.New("short PostgreSQL Query message")
	}
	if message[len(message)-1] != 0 {
		return "", errors.New("PostgreSQL Query message is not null-terminated")
	}
	return string(message[5 : len(message)-1]), nil
}

func (p *DatabaseProxy) serveMySQLReplay(client, upstream net.Conn, cfg DatabaseListenerConfig) error {
	capabilities, err := relayMySQLHandshake(client, upstream)
	if err != nil {
		return err
	}
	reader := bufio.NewReader(client)
	for {
		packet, err := readMySQLPacket(reader)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if len(packet.payload) == 0 {
			return errors.New("empty MySQL command packet")
		}
		switch packet.payload[0] {
		case mysqlQuit:
			return nil
		case mysqlInitDB, mysqlPing, mysqlSetOption, mysqlResetConnection:
			if err := p.discardRequestContext(client.RemoteAddr()); err != nil {
				return err
			}
			if err := relayMySQLControlCommand(client, upstream, packet); err != nil {
				return err
			}
		case mysqlQuery:
			sql, err := mysqlQueryText(packet, capabilities&mysqlClientQueryAttrs != 0)
			if err != nil {
				return err
			}
			if isReplaySessionCommand("mysql", sql) {
				if err := p.discardRequestContext(client.RemoteAddr()); err != nil {
					return err
				}
				if err := relayMySQLSessionQuery(client, upstream, packet, capabilities); err != nil {
					return err
				}
				continue
			}
			response, err := p.queryResponse(client.RemoteAddr(), cfg.DatabaseName, "mysql", sql)
			if err != nil {
				return err
			}
			if _, err := client.Write(response); err != nil {
				return err
			}
		default:
			return fmt.Errorf("MySQL replay does not support command 0x%02x", packet.payload[0])
		}
	}
}

func relayMySQLHandshake(client, upstream net.Conn) (uint32, error) {
	packet, err := readMySQLPacket(upstream)
	if err != nil {
		return 0, err
	}
	if _, err := client.Write(packet.raw); err != nil {
		return 0, err
	}
	serverCapabilities := mysqlServerCapabilities(packet.payload)
	var negotiatedCapabilities uint32
	firstClientReply := true
	needClientReply := true
	for i := 0; i < 8; i++ {
		if needClientReply {
			clientPacket, err := readMySQLPacket(client)
			if err != nil {
				return 0, err
			}
			if firstClientReply && len(clientPacket.payload) >= 4 {
				clientCapabilities := binary.LittleEndian.Uint32(clientPacket.payload[:4])
				negotiatedCapabilities = clientCapabilities & serverCapabilities
			}
			firstClientReply = false
			if _, err := upstream.Write(clientPacket.raw); err != nil {
				return 0, err
			}
		}
		serverPacket, err := readMySQLPacket(upstream)
		if err != nil {
			return 0, err
		}
		if _, err := client.Write(serverPacket.raw); err != nil {
			return 0, err
		}
		if len(serverPacket.payload) == 0 || serverPacket.payload[0] == 0x00 || serverPacket.payload[0] == 0xff {
			return negotiatedCapabilities, nil
		}
		if serverPacket.payload[0] == 0x01 && len(serverPacket.payload) > 1 && serverPacket.payload[1] == 0x03 {
			needClientReply = false
			continue
		}
		needClientReply = true
	}
	return 0, errors.New("MySQL authentication exchange exceeded the supported handshake rounds")
}

func mysqlServerCapabilities(greeting []byte) uint32 {
	if len(greeting) == 0 {
		return 0
	}
	versionEnd := bytes.IndexByte(greeting[1:], 0)
	if versionEnd < 0 {
		return 0
	}
	position := 1 + versionEnd + 1 + 4 + 8 + 1
	if len(greeting) < position+2 {
		return 0
	}
	capabilities := uint32(binary.LittleEndian.Uint16(greeting[position : position+2]))
	position += 2 + 1 + 2
	if len(greeting) < position+2 {
		return capabilities
	}
	capabilities |= uint32(binary.LittleEndian.Uint16(greeting[position:position+2])) << 16
	return capabilities
}

func mysqlQueryText(packet mysqlPacket, queryAttributes bool) (string, error) {
	if len(packet.payload) == 0 || packet.payload[0] != mysqlQuery {
		return "", errors.New("MySQL packet is not COM_QUERY")
	}
	position := 1
	if queryAttributes {
		parameterCount, consumed, err := readMySQLLengthEncodedInteger(packet.payload[position:])
		if err != nil {
			return "", fmt.Errorf("read MySQL query attribute count: %w", err)
		}
		position += consumed
		parameterSetCount, consumed, err := readMySQLLengthEncodedInteger(packet.payload[position:])
		if err != nil {
			return "", fmt.Errorf("read MySQL query attribute set count: %w", err)
		}
		position += consumed
		if parameterSetCount != 1 {
			return "", fmt.Errorf("MySQL COM_QUERY supports one query attribute set, received %d", parameterSetCount)
		}
		if parameterCount != 0 {
			return "", fmt.Errorf("MySQL COM_QUERY query attributes are unsupported (count=%d)", parameterCount)
		}
	}
	if position > len(packet.payload) {
		return "", errors.New("short MySQL COM_QUERY packet")
	}
	return strings.TrimRight(string(packet.payload[position:]), "\x00"), nil
}

func readMySQLLengthEncodedInteger(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	switch data[0] {
	case 0xfc:
		if len(data) < 3 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		return uint64(binary.LittleEndian.Uint16(data[1:3])), 3, nil
	case 0xfd:
		if len(data) < 4 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		return uint64(data[1]) | uint64(data[2])<<8 | uint64(data[3])<<16, 4, nil
	case 0xfe:
		if len(data) < 9 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		return binary.LittleEndian.Uint64(data[1:9]), 9, nil
	case 0xfb, 0xff:
		return 0, 0, fmt.Errorf("invalid MySQL length-encoded integer marker 0x%02x", data[0])
	default:
		return uint64(data[0]), 1, nil
	}
}

type mysqlPacket struct {
	raw     []byte
	payload []byte
}

func readMySQLPacket(reader io.Reader) (mysqlPacket, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return mysqlPacket{}, err
	}
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if length < 0 || length > maxDatabaseFrameBytes {
		return mysqlPacket{}, fmt.Errorf("invalid MySQL packet length %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return mysqlPacket{}, err
	}
	raw := make([]byte, len(header)+len(payload))
	copy(raw, header[:])
	copy(raw[len(header):], payload)
	return mysqlPacket{raw: raw, payload: payload}, nil
}

func (p *DatabaseProxy) queryResponse(clientAddress net.Addr, databaseName, protocol, sql string) ([]byte, error) {
	traceContext, ok, err := p.config.RequestContextMap.Consume(clientAddress.String())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("OBI did not publish a fresh trace context for this database query")
	}
	query, err := DatabaseClientQuery(traceContext, p.config.Gateway.appID, databaseName, protocol, sql)
	if err != nil {
		return nil, err
	}
	queryJSON, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("encode database replay query: %w", err)
	}
	queryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	recorded, err := p.config.Gateway.queryRecord(queryCtx, queryJSON)
	if err != nil {
		return nil, err
	}
	if recorded == nil || recorded.TargetResponse.Body == "" {
		return nil, fmt.Errorf("no %s database response matched trace %s and SQL %s", protocol, traceContext.TraceID, sql)
	}
	if recorded.TargetResponse.Type != RawDatabaseResponseType(protocol) {
		return nil, fmt.Errorf("recorded database response type %q does not match %s", recorded.TargetResponse.Type, protocol)
	}
	response, err := base64.StdEncoding.DecodeString(recorded.TargetResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("decode recorded %s response frames: %w", protocol, err)
	}
	return response, nil
}

func (p *DatabaseProxy) discardRequestContext(clientAddress net.Addr) error {
	if p.config.RequestContextMap == nil || clientAddress == nil {
		return nil
	}
	_, _, err := p.config.RequestContextMap.Consume(clientAddress.String())
	return err
}

func isReplaySessionCommand(protocol, sql string) bool {
	statement := stripLeadingSQLComments(sql)
	statement = strings.TrimSpace(strings.TrimSuffix(statement, ";"))
	if statement == "" {
		return protocol == "postgresql"
	}
	if strings.Contains(statement, ";") {
		return false
	}
	words := strings.Fields(statement)
	if len(words) == 0 {
		return false
	}
	command := strings.ToUpper(words[0])
	switch command {
	case "SET", "BEGIN", "COMMIT", "ROLLBACK":
		if protocol != "postgresql" && protocol != "mysql" {
			return false
		}
		return protocol != "mysql" || !hasMySQLGlobalSetting(statement)
	case "RESET":
		return protocol == "postgresql"
	case "SHOW":
		return protocol == "postgresql" || (protocol == "mysql" && isMySQLSessionMetadataCommand(statement))
	case "START":
		return (protocol == "postgresql" || protocol == "mysql") &&
			len(words) > 1 && strings.EqualFold(words[1], "TRANSACTION")
	case "SELECT":
		return protocol == "mysql" && isMySQLSessionMetadataQuery(statement)
	default:
		return false
	}
}

func stripLeadingSQLComments(sql string) string {
	statement := strings.TrimSpace(sql)
	for statement != "" {
		switch {
		case strings.HasPrefix(statement, "/*"):
			end := strings.Index(statement[2:], "*/")
			if end < 0 {
				return ""
			}
			statement = strings.TrimSpace(statement[end+4:])
		case strings.HasPrefix(statement, "#"):
			if end := strings.IndexByte(statement, '\n'); end >= 0 {
				statement = strings.TrimSpace(statement[end+1:])
			} else {
				return ""
			}
		case strings.HasPrefix(statement, "--") && (len(statement) == 2 || statement[2] == ' ' || statement[2] == '\t' || statement[2] == '\r' || statement[2] == '\n'):
			if end := strings.IndexByte(statement, '\n'); end >= 0 {
				statement = strings.TrimSpace(statement[end+1:])
			} else {
				return ""
			}
		default:
			return statement
		}
	}
	return statement
}

func isMySQLSessionMetadataQuery(statement string) bool {
	upper := strings.ToUpper(statement)
	if strings.Contains(upper, ";") {
		return false
	}
	words := strings.Fields(upper)
	if len(words) == 0 || words[0] != "SELECT" {
		return false
	}
	for _, word := range words[1:] {
		keyword := strings.Trim(word, "(),")
		if keyword == "JOIN" || keyword == "UNION" || keyword == "INTO" || keyword == "SELECT" {
			return false
		}
	}
	if from := mysqlFromTable(words); from != "" &&
		!strings.HasPrefix(from, "PERFORMANCE_SCHEMA.") &&
		!strings.HasPrefix(from, "INFORMATION_SCHEMA.") {
		return false
	}
	// JDBC drivers query server/session properties while opening a connection.
	// These values describe the connection or server and are not application
	// table data, so they can be read from the live database during replay.
	if strings.Contains(upper, "@@") || strings.Contains(upper, "DATABASE(") ||
		strings.Contains(upper, "VERSION(") || strings.Contains(upper, "CURRENT_USER(") ||
		strings.Contains(upper, "CONNECTION_ID(") || strings.Contains(upper, "USER(") {
		return true
	}
	return strings.Contains(upper, "PERFORMANCE_SCHEMA.") || strings.Contains(upper, "INFORMATION_SCHEMA.")
}

func mysqlFromTable(words []string) string {
	for index, word := range words {
		if strings.Trim(word, "(),") != "FROM" {
			continue
		}
		if index+1 >= len(words) {
			return ""
		}
		table := strings.TrimLeft(words[index+1], "([")
		table = strings.TrimRight(table, "),;")
		for _, token := range words[index+2:] {
			keyword := strings.Trim(token, "(),")
			if keyword == "WHERE" || keyword == "GROUP" || keyword == "ORDER" || keyword == "HAVING" || keyword == "LIMIT" {
				break
			}
			if strings.Contains(token, ",") {
				return "<multiple tables>"
			}
		}
		return table
	}
	return ""
}

func isMySQLSessionMetadataCommand(statement string) bool {
	words := strings.Fields(strings.ToUpper(statement))
	if len(words) < 2 {
		return false
	}
	if words[1] == "VARIABLES" || words[1] == "STATUS" || words[1] == "COLLATION" ||
		words[1] == "CHARACTER" || words[1] == "ENGINES" || words[1] == "WARNINGS" {
		return !strings.Contains(statement, ";")
	}
	return false
}

func hasMySQLGlobalSetting(statement string) bool {
	for _, word := range strings.Fields(strings.ToUpper(statement)) {
		keyword := strings.Trim(word, "(),")
		keyword = strings.TrimPrefix(keyword, "@@")
		if keyword == "GLOBAL" || strings.HasPrefix(keyword, "GLOBAL.") ||
			keyword == "PERSIST" || strings.HasPrefix(keyword, "PERSIST.") ||
			keyword == "PERSIST_ONLY" || strings.HasPrefix(keyword, "PERSIST_ONLY.") ||
			keyword == "PASSWORD" {
			return true
		}
	}
	return false
}

func relayPostgresSessionQuery(client, upstream net.Conn, query []byte) error {
	if _, err := upstream.Write(query); err != nil {
		return err
	}
	reader := bufio.NewReader(upstream)
	for {
		message, err := readPostgresMessage(reader)
		if err != nil {
			return err
		}
		if _, err := client.Write(message); err != nil {
			return err
		}
		if len(message) > 0 && message[0] == postgresReadyForQuery {
			return nil
		}
	}
}

func relayMySQLSessionQuery(client, upstream io.ReadWriter, query mysqlPacket, capabilities uint32) error {
	if _, err := upstream.Write(query.raw); err != nil {
		return err
	}
	response, err := readMySQLPacket(upstream)
	if err != nil {
		return err
	}
	if err := writeMySQLPacket(client, response); err != nil {
		return err
	}
	if isMySQLErrorPacket(response) || isMySQLOKPacket(response) {
		return nil
	}
	if len(response.payload) > 0 && response.payload[0] == 0xfb {
		return errors.New("MySQL replay does not support LOCAL INFILE session commands")
	}
	columnCount, _, err := readMySQLLengthEncodedInteger(response.payload)
	if err != nil {
		return fmt.Errorf("read MySQL session result column count: %w", err)
	}
	if columnCount > uint64(maxDatabaseFrameBytes) {
		return fmt.Errorf("invalid MySQL session result column count %d", columnCount)
	}
	for i := uint64(0); i < columnCount; i++ {
		column, err := readMySQLPacket(upstream)
		if err != nil {
			return err
		}
		if err := writeMySQLPacket(client, column); err != nil {
			return err
		}
	}
	if capabilities&mysqlClientDeprecateEOF == 0 {
		metadataEnd, err := readMySQLPacket(upstream)
		if err != nil {
			return err
		}
		if err := writeMySQLPacket(client, metadataEnd); err != nil {
			return err
		}
		if isMySQLErrorPacket(metadataEnd) {
			return nil
		}
	}
	for {
		row, err := readMySQLPacket(upstream)
		if err != nil {
			return err
		}
		if err := writeMySQLPacket(client, row); err != nil {
			return err
		}
		if isMySQLErrorPacket(row) || isMySQLResultTerminator(row, capabilities) {
			return nil
		}
	}
}

func relayMySQLControlCommand(client, upstream io.ReadWriter, command mysqlPacket) error {
	if _, err := upstream.Write(command.raw); err != nil {
		return err
	}
	response, err := readMySQLPacket(upstream)
	if err != nil {
		return err
	}
	return writeMySQLPacket(client, response)
}

func writeMySQLPacket(destination io.Writer, packet mysqlPacket) error {
	_, err := destination.Write(packet.raw)
	return err
}

func isMySQLErrorPacket(packet mysqlPacket) bool {
	return len(packet.payload) > 0 && packet.payload[0] == 0xff
}

func isMySQLOKPacket(packet mysqlPacket) bool {
	return len(packet.payload) > 1 && packet.payload[0] == 0x00
}

func isMySQLResultTerminator(packet mysqlPacket, capabilities uint32) bool {
	if len(packet.payload) == 0 || packet.payload[0] != 0xfe {
		return false
	}
	return len(packet.payload) < 9 || capabilities&mysqlClientDeprecateEOF != 0
}
