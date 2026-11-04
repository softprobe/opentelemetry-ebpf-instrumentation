// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"
)

type fixedRequestContextReader struct {
	context  RequestTraceContext
	contexts []RequestTraceContext
	address  net.Addr
	calls    int
}

func (r *fixedRequestContextReader) Consume(address string) (RequestTraceContext, bool, error) {
	parsedAddress, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return RequestTraceContext{}, false, err
	}
	r.address = parsedAddress
	index := r.calls
	r.calls++
	if len(r.contexts) > 0 {
		if index >= len(r.contexts) {
			return RequestTraceContext{}, false, nil
		}
		return r.contexts[index], true, nil
	}
	return r.context, true, nil
}

func TestIsReplaySessionCommand(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		sql      string
		want     bool
	}{
		{name: "postgres driver setting", protocol: "postgresql", sql: "SET extra_float_digits = 3", want: true},
		{name: "postgres empty query", protocol: "postgresql", sql: "", want: true},
		{name: "postgres transaction boundary", protocol: "postgresql", sql: "BEGIN", want: true},
		{name: "mysql character set", protocol: "mysql", sql: "SET NAMES utf8mb4", want: true},
		{name: "mysql commented character set", protocol: "mysql", sql: "/* mysql-connector */ SET NAMES utf8mb4", want: true},
		{name: "mysql transaction boundary", protocol: "mysql", sql: "COMMIT", want: true},
		{name: "mysql server variables", protocol: "mysql", sql: "/* connector */ SELECT @@session.auto_increment_increment", want: true},
		{name: "mysql performance schema metadata", protocol: "mysql", sql: "SELECT VARIABLE_NAME FROM performance_schema.session_variables", want: true},
		{name: "mysql variables command", protocol: "mysql", sql: "SHOW VARIABLES LIKE 'transaction_isolation'", want: true},
		{name: "mysql global setting changes server", protocol: "mysql", sql: "SET GLOBAL max_connections = 100", want: false},
		{name: "mysql qualified global setting changes server", protocol: "mysql", sql: "SET @@GLOBAL.max_connections = 100", want: false},
		{name: "mysql persist setting changes server", protocol: "mysql", sql: "SET PERSIST max_connections = 100", want: false},
		{name: "mysql password change is not a session setting", protocol: "mysql", sql: "SET PASSWORD FOR user = 'secret'", want: false},
		{name: "mysql metadata expression cannot bypass application table", protocol: "mysql", sql: "SELECT @@session.autocommit FROM ota_payments", want: false},
		{name: "mysql table metadata is replayed", protocol: "mysql", sql: "SHOW TABLES", want: false},
		{name: "table write is replayed", protocol: "postgresql", sql: "INSERT INTO ota_orders VALUES (1)", want: false},
		{name: "table read is replayed", protocol: "mysql", sql: "SELECT * FROM ota_payments", want: false},
		{name: "application SELECT is replayed", protocol: "mysql", sql: "SELECT DATABASE_NAME FROM ota_payments", want: false},
		{name: "multi statement is not forwarded", protocol: "mysql", sql: "SET x=1; DELETE FROM ota_payments", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, isReplaySessionCommand(test.protocol, test.sql))
		})
	}
}

func TestDatabaseProxyQueriesExistingAPIWithContextForThisSQLRequest(t *testing.T) {
	const traceID = "00112233445566778899aabbccddeeff"
	const sql = "INSERT INTO ota_payments (payment_id) VALUES ('payment-1')"
	responseFrames := []byte{0x07, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	compressed := zstdJSON(t, Mocker{TargetResponse: Target{
		Type: RawDatabaseResponseType("mysql"),
		Body: base64.StdEncoding.EncodeToString(responseFrames),
	}})
	var received Mocker
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/storage/record/query", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&received))
		_, _ = w.Write(compressed)
	}))
	defer backend.Close()
	recordAPI, err := url.Parse(backend.URL + "/api/storage/record/query")
	require.NoError(t, err)
	gateway, err := NewGateway(GatewayConfig{Mode: ReplayMode, AppID: "travel-ota", RecordAPI: recordAPI})
	require.NoError(t, err)
	contextReader := &fixedRequestContextReader{context: RequestTraceContext{TraceID: traceID}}
	proxy, err := NewDatabaseProxy(DatabaseProxyConfig{
		MySQL:             DatabaseListenerConfig{Listen: "127.0.0.1:0", Upstream: "127.0.0.1:3306"},
		RequestContextMap: contextReader,
		Gateway:           gateway,
	})
	require.NoError(t, err)

	address := &net.TCPAddr{IP: net.ParseIP("192.0.2.15"), Port: 43127}
	got, err := proxy.queryResponse(address, "", "mysql", sql)
	require.NoError(t, err)
	require.Equal(t, responseFrames, got)
	require.Equal(t, 1, contextReader.calls)
	require.Equal(t, address, contextReader.address)
	require.Equal(t, traceID, received.TraceID)
	require.Equal(t, "travel-ota", received.AppID)
	require.Equal(t, "@ota_payments@INSERT@OBI.query", received.OperationName)
	require.Equal(t, sql, received.TargetRequest.Body)
	require.Equal(t, "mysql", received.TargetRequest.Attributes["protocol"])
}

func TestDatabaseProxyRefreshesTraceForEachQueryOnPooledConnection(t *testing.T) {
	const sql = "SELECT order_json FROM ota_orders WHERE order_id = 'order-1'"
	responseFrames := []byte{0x07, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	compressed := zstdJSON(t, Mocker{TargetResponse: Target{
		Type: RawDatabaseResponseType("postgresql"),
		Body: base64.StdEncoding.EncodeToString(responseFrames),
	}})
	queries := make(chan Mocker, 2)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var query Mocker
		require.NoError(t, json.NewDecoder(r.Body).Decode(&query))
		queries <- query
		_, _ = w.Write(compressed)
	}))
	defer backend.Close()
	recordAPI, err := url.Parse(backend.URL + "/api/storage/record/query")
	require.NoError(t, err)
	gateway, err := NewGateway(GatewayConfig{Mode: ReplayMode, AppID: "travel-ota", RecordAPI: recordAPI})
	require.NoError(t, err)
	contextReader := &fixedRequestContextReader{contexts: []RequestTraceContext{
		{TraceID: "00112233445566778899aabbccddeeff"},
		{TraceID: "ffeeddccbbaa99887766554433221100"},
	}}
	proxy, err := NewDatabaseProxy(DatabaseProxyConfig{
		Postgres:          DatabaseListenerConfig{Listen: "127.0.0.1:0", Upstream: "127.0.0.1:5432", DatabaseName: "travel_orders"},
		RequestContextMap: contextReader,
		Gateway:           gateway,
	})
	require.NoError(t, err)
	pooledClientAddress := &net.TCPAddr{IP: net.ParseIP("192.0.2.15"), Port: 43127}

	for i := 0; i < 2; i++ {
		got, queryErr := proxy.queryResponse(pooledClientAddress, "travel_orders", "postgresql", sql)
		require.NoError(t, queryErr)
		require.Equal(t, responseFrames, got)
	}

	require.Equal(t, 2, contextReader.calls)
	require.Equal(t, "00112233445566778899aabbccddeeff", (<-queries).TraceID)
	require.Equal(t, "ffeeddccbbaa99887766554433221100", (<-queries).TraceID)
}

func TestReadPostgresMessageKeepsTheCompleteQueryFrame(t *testing.T) {
	sql := "SELECT booking_json FROM ota_orders"
	body := append([]byte(sql), 0)
	frame := make([]byte, 5+len(body))
	frame[0] = postgresQuery
	binary.BigEndian.PutUint32(frame[1:5], uint32(4+len(body)))
	copy(frame[5:], body)

	message, err := readPostgresMessage(bytes.NewReader(frame))
	require.NoError(t, err)
	require.Equal(t, frame, message)
	gotSQL, err := postgresQueryText(message)
	require.NoError(t, err)
	require.Equal(t, sql, gotSQL)
}

func TestReadMySQLPacketKeepsTheCompleteCommand(t *testing.T) {
	payload := append([]byte{mysqlQuery}, []byte("SELECT 1")...)
	packet := make([]byte, 4+len(payload))
	packet[0] = byte(len(payload))
	packet[1] = byte(len(payload) >> 8)
	packet[2] = byte(len(payload) >> 16)
	packet[3] = 0
	copy(packet[4:], payload)

	got, err := readMySQLPacket(bytes.NewReader(packet))
	require.NoError(t, err)
	require.Equal(t, payload, got.payload)
	require.Equal(t, packet, got.raw)
}

func TestMySQLQueryTextStripsNegotiatedQueryAttributeEnvelope(t *testing.T) {
	packet := mysqlPacket{payload: append(
		[]byte{mysqlQuery, 0x00, 0x01},
		[]byte("/* mysql-connector */ SET NAMES utf8mb4")...,
	)}

	sql, err := mysqlQueryText(packet, true)
	require.NoError(t, err)
	require.Equal(t, "/* mysql-connector */ SET NAMES utf8mb4", sql)
}

func TestMySQLQueryTextRejectsUnsupportedAttributes(t *testing.T) {
	packet := mysqlPacket{payload: []byte{mysqlQuery, 0x01, 0x01, 'x'}}

	_, err := mysqlQueryText(packet, true)
	require.ErrorContains(t, err, "query attributes are unsupported")
}

func TestRelayMySQLSessionQueryForwardsCompleteLegacyResultSet(t *testing.T) {
	query := mysqlTestPacketValue(t, 0, append([]byte{mysqlQuery}, []byte("SHOW VARIABLES")...))
	response := bytes.Join([][]byte{
		mysqlTestPacket(1, []byte{0x02}),      // two columns
		mysqlTestPacket(2, []byte{0x03, 'c'}), // column definition
		mysqlTestPacket(3, []byte{0x03, 'v'}), // column definition
		mysqlTestPacket(4, []byte{0xfe, 0, 0, 2, 0}),
		mysqlTestPacket(5, []byte{0x01, 'x', 0x01, '1'}), // row
		mysqlTestPacket(6, []byte{0xfe, 0, 0, 2, 0}),
	}, nil)
	upstream := &mysqlTestReadWriter{reader: bytes.NewReader(response)}
	client := &mysqlTestReadWriter{}

	require.NoError(t, relayMySQLSessionQuery(client, upstream, query, 0))
	require.Equal(t, query.raw, upstream.writer.Bytes())
	require.Equal(t, response, client.writer.Bytes())
}

func TestRelayMySQLSessionQueryForwardsDeprecateEOFResultSet(t *testing.T) {
	query := mysqlTestPacketValue(t, 0, append([]byte{mysqlQuery}, []byte("SELECT @@version")...))
	response := bytes.Join([][]byte{
		mysqlTestPacket(1, []byte{0x01}),
		mysqlTestPacket(2, []byte{0x03, 'c'}),
		mysqlTestPacket(3, []byte{0x01, '8'}),
		mysqlTestPacket(4, []byte{0xfe, 0, 0, 2, 0, 0, 0}),
	}, nil)
	upstream := &mysqlTestReadWriter{reader: bytes.NewReader(response)}
	client := &mysqlTestReadWriter{}

	require.NoError(t, relayMySQLSessionQuery(client, upstream, query, mysqlClientDeprecateEOF))
	require.Equal(t, response, client.writer.Bytes())
}

func TestRelayMySQLSessionQueryForwardsOKPacket(t *testing.T) {
	query := mysqlTestPacketValue(t, 0, append([]byte{mysqlQuery}, []byte("SET NAMES utf8mb4")...))
	response := mysqlTestPacket(1, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})
	upstream := &mysqlTestReadWriter{reader: bytes.NewReader(response)}
	client := &mysqlTestReadWriter{}

	require.NoError(t, relayMySQLSessionQuery(client, upstream, query, 0))
	require.Equal(t, response, client.writer.Bytes())
}

func TestRelayMySQLControlCommandForwardsCommandAndResponse(t *testing.T) {
	command := mysqlTestPacketValue(t, 0, []byte{mysqlPing})
	response := mysqlTestPacket(1, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})
	upstream := &mysqlTestReadWriter{reader: bytes.NewReader(response)}
	client := &mysqlTestReadWriter{}

	require.NoError(t, relayMySQLControlCommand(client, upstream, command))
	require.Equal(t, command.raw, upstream.writer.Bytes())
	require.Equal(t, response, client.writer.Bytes())
}

type mysqlTestReadWriter struct {
	reader io.Reader
	writer bytes.Buffer
}

func (rw *mysqlTestReadWriter) Read(data []byte) (int, error) {
	return rw.reader.Read(data)
}

func (rw *mysqlTestReadWriter) Write(data []byte) (int, error) {
	return rw.writer.Write(data)
}

func mysqlTestPacket(sequence byte, payload []byte) []byte {
	packet := make([]byte, 4+len(payload))
	packet[0] = byte(len(payload))
	packet[1] = byte(len(payload) >> 8)
	packet[2] = byte(len(payload) >> 16)
	packet[3] = sequence
	copy(packet[4:], payload)
	return packet
}

func mysqlTestPacketValue(t *testing.T, sequence byte, payload []byte) mysqlPacket {
	t.Helper()
	packet, err := readMySQLPacket(bytes.NewReader(mysqlTestPacket(sequence, payload)))
	require.NoError(t, err)
	return packet
}

func zstdJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	writer, err := zstd.NewWriter(nil)
	require.NoError(t, err)
	defer writer.Close()
	return writer.EncodeAll(data, nil)
}
