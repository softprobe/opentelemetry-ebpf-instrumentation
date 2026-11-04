// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.opentelemetry.io/obi/pkg/softprobe"
)

func runSoftprobeGateway(args []string) (bool, int) {
	if len(args) == 0 || args[0] != "softprobe-gateway" {
		return false, 0
	}

	flags := flag.NewFlagSet("obi softprobe-gateway", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	mode := flags.String("mode", softprobe.RecordMode, "gateway mode: record or replay")
	listen := flags.String("listen", "127.0.0.1:15001", "HTTP listen address")
	appID := flags.String("app-id", "", "Softprobe application ID (required for replay and OTLP recording)")
	upstream := flags.String("upstream", "", "record-mode HTTP upstream URL")
	recordAPI := flags.String("record-api", "http://127.0.0.1:18090/api/storage/record/query", "existing Softprobe recording query API URL")
	traceAPI := flags.String("trace-api", "", "existing OTLP trace ingest API URL (enables recording in record mode)")
	postgresListen := flags.String("postgres-listen", "", "optional PostgreSQL TCP listen address")
	postgresUpstream := flags.String("postgres-upstream", "", "PostgreSQL upstream host:port")
	postgresDatabase := flags.String("postgres-database", "", "PostgreSQL database name used for replay matching")
	mysqlListen := flags.String("mysql-listen", "", "optional MySQL TCP listen address")
	mysqlUpstream := flags.String("mysql-upstream", "", "MySQL upstream host:port")
	mysqlDatabase := flags.String("mysql-database", "", "MySQL database name used for replay matching")
	contextMapPath := flags.String("request-context-map", softprobe.DefaultRequestContextMapPath, "OBI per-request trace context map path")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return true, 0
		}
		return true, 2
	}

	upstreamURL, err := parseGatewayURL(*upstream)
	if err != nil {
		slog.Error("invalid upstream URL", "error", err)
		return true, 2
	}
	recordAPIURL, err := parseGatewayURL(*recordAPI)
	if err != nil {
		slog.Error("invalid record API URL", "error", err)
		return true, 2
	}
	traceAPIURL, err := parseGatewayURL(*traceAPI)
	if err != nil {
		slog.Error("invalid OTLP trace API URL", "error", err)
		return true, 2
	}
	var contextMap softprobe.RequestTraceContextReader
	if *mode == softprobe.ReplayMode || *traceAPI != "" {
		contextMap, err = softprobe.NewPinnedRequestContextMap(*contextMapPath)
		if err != nil {
			slog.Error("configure OBI request context map", "error", err)
			return true, 2
		}
	}
	gateway, err := softprobe.NewGateway(softprobe.GatewayConfig{
		Mode:              *mode,
		AppID:             *appID,
		Upstream:          upstreamURL,
		RecordAPI:         recordAPIURL,
		TraceAPI:          traceAPIURL,
		RequestContextMap: contextMap,
	})
	if err != nil {
		slog.Error("configure Softprobe gateway", "error", err)
		return true, 2
	}

	var databaseProxy *softprobe.DatabaseProxy
	if *postgresListen != "" || *mysqlListen != "" {
		databaseProxy, err = softprobe.NewDatabaseProxy(softprobe.DatabaseProxyConfig{
			Postgres: softprobe.DatabaseListenerConfig{
				Listen:       *postgresListen,
				Upstream:     *postgresUpstream,
				DatabaseName: *postgresDatabase,
			},
			MySQL: softprobe.DatabaseListenerConfig{
				Listen:       *mysqlListen,
				Upstream:     *mysqlUpstream,
				DatabaseName: *mysqlDatabase,
			},
			RequestContextMap: contextMap,
			Gateway:           gateway,
		})
		if err != nil {
			slog.Error("configure Softprobe database proxy", "error", err)
			return true, 2
		}
	}

	server := &http.Server{
		Addr:              *listen,
		Handler:           gateway,
		ReadHeaderTimeout: 5 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	databaseProxyErrors := make(chan error, 1)
	if databaseProxy != nil {
		go func() {
			if err := databaseProxy.Listen(ctx); err != nil {
				databaseProxyErrors <- err
				stop()
			}
		}()
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("Softprobe gateway shutdown failed", "error", err)
		}
	}()

	slog.Info("Softprobe OBI gateway listening", "addr", *listen, "mode", *mode)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("Softprobe gateway server failed", "error", err)
		return true, 1
	}
	select {
	case err := <-databaseProxyErrors:
		slog.Error("Softprobe database proxy failed", "error", err)
		return true, 1
	default:
	}
	return true, 0
}

func parseGatewayURL(value string) (*url.URL, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("URL scheme must be http or https")
	}
	if parsed.Host == "" {
		return nil, errors.New("URL must include a host")
	}
	return parsed, nil
}
