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

func runSoftprobeIngress(args []string) (bool, int) {
	if len(args) == 0 || args[0] != "softprobe-ingress" {
		return false, 0
	}

	flags := flag.NewFlagSet("obi softprobe-ingress", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	listen := flags.String("listen", "127.0.0.1:15002", "HTTP listen address")
	appID := flags.String("app-id", "", "Softprobe application ID")
	upstream := flags.String("upstream", "", "application upstream URL")
	traceAPI := flags.String("trace-api", "", "existing OTLP trace ingest API URL")
	recordAPI := flags.String("record-api", "", "existing Softprobe record query API URL for replay result writes")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return true, 0
		}
		return true, 2
	}

	upstreamURL, err := parseGatewayURL(*upstream)
	if err != nil {
		slog.Error("invalid ingress upstream URL", "error", err)
		return true, 2
	}
	traceAPIURL, err := parseGatewayURL(*traceAPI)
	if err != nil {
		slog.Error("invalid OTLP trace API URL", "error", err)
		return true, 2
	}
	var recordAPIURL *url.URL
	if *recordAPI != "" {
		recordAPIURL, err = parseGatewayURL(*recordAPI)
		if err != nil {
			slog.Error("invalid ingress record API URL", "error", err)
			return true, 2
		}
	}
	ingress, err := softprobe.NewIngressGateway(softprobe.IngressGatewayConfig{
		AppID:     *appID,
		Upstream:  upstreamURL,
		TraceAPI:  traceAPIURL,
		RecordAPI: recordAPIURL,
	})
	if err != nil {
		slog.Error("configure Softprobe ingress gateway", "error", err)
		return true, 2
	}

	server := &http.Server{
		Addr:              *listen,
		Handler:           ingress,
		ReadHeaderTimeout: 5 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("Softprobe ingress shutdown failed", "error", err)
		}
	}()

	slog.Info("Softprobe OBI ingress gateway listening", "addr", *listen, "upstream", upstreamURL)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("Softprobe ingress server failed", "error", err)
		return true, 1
	}
	return true, 0
}
