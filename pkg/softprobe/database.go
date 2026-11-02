// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/sqlprune"
)

const (
	CategoryDatabase        = "Database"
	databaseQueryOperation  = "OBI.query"
	databaseStatementType   = "STATEMENT"
	databaseStatementMethod = "execute"
)

// RequestTraceContext is the trace context OBI observes for one client
// request. The same connection may carry requests from different traces.
type RequestTraceContext struct {
	TraceID      string
	ParentSpanID string
	ReplayID     string
	Flags        uint32
}

// RequestTraceContextReader consumes OBI's per-request trace handoff for the
// client-side TCP address observed by a protocol gateway.
type RequestTraceContextReader interface {
	Consume(clientAddress string) (RequestTraceContext, bool, error)
}

// DatabaseClientQuery constructs a legacy-compatible Database-category query
// for the existing /api/storage/record/query endpoint. The caller obtains the
// context from OBI's per-request context handoff.
func DatabaseClientQuery(ctx RequestTraceContext, appID, databaseName, protocol, sql string) (Mocker, error) {
	if !validHexID(ctx.TraceID, traceIDLength) {
		return Mocker{}, errors.New("database replay requires a valid trace ID")
	}
	if appID == "" {
		return Mocker{}, errors.New("database replay requires a Softprobe application ID")
	}
	if protocol != "postgresql" && protocol != "mysql" {
		return Mocker{}, fmt.Errorf("unsupported database replay protocol %q", protocol)
	}
	operation, tables := sqlprune.SQLParseOperationAndTables(sql)
	if operation == "" {
		command := "<empty>"
		if words := strings.Fields(strings.TrimSpace(sql)); len(words) > 0 {
			command = strings.ToUpper(words[0])
		}
		return Mocker{}, fmt.Errorf("database replay requires a recognized SQL operation for command %q", command)
	}
	table := sqlprune.SQLTargetCollection(operation, tables)
	operationName := databaseOperationName(databaseName, table, operation)
	return Mocker{
		CategoryType:  CategoryType{Name: CategoryDatabase},
		TraceID:       strings.ToLower(ctx.TraceID),
		ReplayID:      ctx.ReplayID,
		AppID:         appID,
		OperationName: operationName,
		TargetRequest: Target{
			Body: sql,
			Type: javaStringType,
			Attributes: map[string]any{
				"sql":           sql,
				"dbName":        databaseName,
				"protocol":      protocol,
				"statementType": databaseStatementType,
				"methodName":    databaseStatementMethod,
			},
		},
	}, nil
}

// DatabaseRecording maps OBI's parsed SQL span and captured wire frames into
// the backend's existing Database mocker contract.
func DatabaseRecording(span request.Span, appID string) (Mocker, error) {
	if span.Type != request.EventTypeSQLClient {
		return Mocker{}, errors.New("span is not a SQL client span")
	}
	if span.Statement == "" {
		return Mocker{}, errors.New("SQL client span has no statement payload")
	}
	protocol := databaseProtocolName(span)
	if protocol == "" {
		return Mocker{}, fmt.Errorf("unsupported SQL protocol subtype %d", span.SubType)
	}
	sql := strings.TrimSpace(span.Statement)
	operation := strings.ToUpper(span.Method)
	if operation == "" {
		operation, _ = sqlprune.SQLParseOperationAndTables(sql)
	}
	if operation == "" {
		return Mocker{}, errors.New("SQL client span has no operation name")
	}
	table := span.Path
	if table == "" {
		_, tables := sqlprune.SQLParseOperationAndTables(sql)
		table = sqlprune.SQLTargetCollection(operation, tables)
	}
	responsePayload := base64.StdEncoding.EncodeToString(span.SoftprobeResponsePayload)
	mocker := Mocker{
		CategoryType: CategoryType{Name: CategoryDatabase},
		TraceID:      span.TraceID.String(),
		AppID:        appID,
		SpanID:       span.SpanID.String(),
		ParentSpanID: span.ParentSpanID.String(),
		SegmentID:    span.ParentSpanID.String(),
		SpanKind:     "CLIENT",
		CreationTime: time.Now().UnixMilli(),
		OperationName: databaseOperationName(
			span.DBNamespace,
			table,
			operation,
		),
		TargetRequest: Target{
			Body: sql,
			Type: javaStringType,
			Attributes: map[string]any{
				"sql":           sql,
				"dbName":        span.DBNamespace,
				"protocol":      protocol,
				"statementType": databaseStatementType,
				"methodName":    databaseStatementMethod,
			},
		},
		TargetResponse: Target{
			Body: responsePayload,
			Type: RawDatabaseResponseType(protocol),
			Attributes: map[string]any{
				"protocol": protocol,
			},
		},
	}
	if len(span.SoftprobeRequestPayload) == 0 || len(span.SoftprobeResponsePayload) == 0 {
		return Mocker{}, errors.New("SQL client span is missing captured wire payloads")
	}
	return mocker, nil
}

// RawDatabaseResponseType identifies an OBI-captured framed database response.
func RawDatabaseResponseType(protocol string) string {
	return "softprobe.obi.raw." + protocol
}

func databaseOperationName(databaseName, table, operation string) string {
	return databaseName + "@" + table + "@" + operation + "@" + databaseQueryOperation
}

func databaseProtocolName(span request.Span) string {
	switch span.SubType {
	case int(request.DBPostgres):
		return "postgresql"
	case int(request.DBMySQL):
		return "mysql"
	default:
		return ""
	}
}

func validHexID(value string, size int) bool {
	if len(value) != size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == size && !allZero(decoded)
}
