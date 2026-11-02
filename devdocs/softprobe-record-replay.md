# Softprobe recording and replay prototype

This fork adds an opt-in payload path for OBI spans and HTTP entry/dependency
gateways for the Softprobe demo. OBI remains the process-external instrumenter:
protocol buffers are collected from sockets and attached to the span OBI already
emits. The ingress gateway records replayable application entry requests. The
dependency gateway reads the W3C `traceparent` propagated by OBI, queries the
existing Softprobe replay API, and returns the recorded response to the caller.

## Compatibility contract

- Record through the existing OTLP/HTTP `POST /v1/traces` endpoint. OBI emits
  the existing `sp_*` span attributes consumed by Softprobe's OTLP receiver.
- Record HTTP application entrypoints as existing `Servlet` mockers through the
  same OTLP endpoint. The ingress gateway preserves a valid incoming W3C
  `traceparent` and creates one when an external caller did not send it.
- Replay through `POST /api/storage/record/query`, sending the existing
  `SpMocker` query shape and decoding its Zstandard-compressed JSON response.
- Use existing `HttpClient` recordings: request method, URL path, query,
  content type, and request body follow the Java agent's HTTP client match key;
  response content is represented as its `HttpResponseWrapper` JSON.
- Preserve standard OBI trace context propagation. The gateway prefers a valid
  W3C `traceparent`; when an HTTP client does not propagate it, the gateway can
  use OBI's per-request context handoff for the accepted TCP connection.

## Database capture and replay prototype

OBI's SQL spans for PostgreSQL and MySQL are adapted to the existing Softprobe
`Database` mocker category and sent through the same OTLP trace endpoint as
`Servlet` and `HttpClient`. OBI resolves the active application trace when each
query starts, then observes that query and its response on the database
connection. SQL packets do not contain a trace ID. A standalone TCP proxy
cannot infer one from the protocol, but OBI can still put the SQL span on the
active trace because it tracks context inside the instrumented process.

OBI hands that context to local gateways through the versioned pinned
`sp_request_ctx_v1` BPF map. The map key is the client-side IP and ephemeral
port; the value contains the trace and parent span IDs for the latest observed
client request. On a pooled JDBC connection, each sequential SQL statement
refreshes the value for the same socket before its packets reach the proxy. The
gateway consumes the entry for that request, then queries the existing
`/api/storage/record/query` API by trace ID and the existing SQL match fields.
The same handoff supports HTTP clients that do not send `traceparent`; a valid
W3C header still takes precedence and the map entry is consumed to avoid stale
context. This keeps context out of SQL text and leaves the backend API and
recording shape unchanged.

The demo replay adapter currently supports PostgreSQL simple-query mode and
MySQL `COM_QUERY` on sequential requests. Extended PostgreSQL messages, MySQL
binary prepared statements, pipelined or multiplexed requests on a single TCP
connection, app-to-proxy TLS, and other database protocols still need protocol
adapters. PostgreSQL replay startup uses the configured database name; OBI's
current MySQL SQL spans do not expose a database namespace, so MySQL matching
uses the remaining existing `Database` request fields and trace ID.

MySQL replay reads the negotiated capabilities so it can remove the MySQL 8.4
`COM_QUERY` attribute envelope before matching SQL. It relays the driver's
connection setup (`SET`, selected metadata `SHOW`/`SELECT` commands, ping,
database selection, and reset) to the live server. The metadata allowlist rejects
application-table reads and global/persistent settings; recognized application
SQL still requires a fresh OBI context-map entry and returns only the recorded
database response.

## Payload capture

Enable `capture.instrumentation.record_payloads` in OBI config v2 to attach the
captured request and response wire bytes to supported protocol spans. This
includes protocols OBI already parses, such as HTTP, PostgreSQL, and MySQL. The
capture is bounded by OBI's protocol buffer sizes. HTTP payloads are converted
to the legacy Softprobe HTTP target shape; PostgreSQL and MySQL SQL spans are
converted to the existing `Database` target shape with the wire response kept
as base64 in `targetResponse.body` for gateway replay.

## Demo-ota proof

The runnable harness is in [`demo/demo-ota`](../demo/demo-ota/README.md). It
runs `travel-ota` without `sp-agent-java`, routes test traffic through the OBI
ingress gateway, points its airline HTTP client through the dependency
gateway, and runs this OBI fork in a sidecar sharing the demo process namespace.
Both gateways export compatible mocker spans directly to the backend's existing
OTLP HTTP ingestion endpoint (the local Vector pipeline drops traces). During
replay plans target `http://softprobe-ingress:15002`; ingress restores the
recorded trace ID from Softprobe's replay `tracestate` before forwarding to
`travel-ota`. Its outbound calls pass through the dependency gateway, which
queries the same backend by trace ID and carries the replay ID into the existing
query API. After the app responds, ingress writes the `Servlet` replay result to
that same API for backend comparison. The demo enables OBI's optional Java
runtime context helper for propagation across Java server and client spans; it
does not use `sp-agent-java`.

Apache HttpAsyncClient 4 creates its HTTP request on the servlet worker and
writes it later on an `I/O dispatcher` thread. The OBI Java helper tracks the
producer's originating thread and emits the existing OBI task-parent context
from `produceContent`, where the reactor writes the request. This keeps the
baggage-purchase dependency under the recorded or replayed request trace.

To exercise the existing OTA recording and replay API cases against that same
Docker backend, run recording and replay as separate steps. Replay needs the
dependency gateway switched to replay mode after recording finishes:

```bash
cd /Users/bill/src/arex/e2e
SOFTPROBE_GATEWAY_MODE=record docker compose \
  -f ../sp-obi/demo/demo-ota/docker-compose.yml \
  up -d --force-recreate softprobe-gateway

SP_BIN=../cli/sp \
SP_API_URL=http://127.0.0.1:18090 \
OTA_BASE_URL=http://127.0.0.1:18080 \
SP_E2E_REPLAY_ENV=http://softprobe-ingress:15002 \
SP_OBI_DATABASE_E2E=1 \
./.venv/bin/python -m pytest -v test_ota_recording_e2e.py test_ota_database_recording_e2e.py

SOFTPROBE_GATEWAY_MODE=replay docker compose \
  -f ../sp-obi/demo/demo-ota/docker-compose.yml \
  up -d --force-recreate softprobe-gateway

SP_BIN=../cli/sp \
SP_API_URL=http://127.0.0.1:18090 \
OTA_BASE_URL=http://127.0.0.1:18080 \
SP_E2E_REPLAY_ENV=http://softprobe-ingress:15002 \
./.venv/bin/python -m pytest -v test_ota_replay_api_e2e.py
```

These tests verify all six OTA entry APIs, fresh outbound `HttpClient` rows
linked to this run's Servlet traces, and a replay plan with six successes and
no failures or errors. The traceparent used by the extra search case is unique
per run so an older backend record cannot shadow the fresh recording.
Java-agent-only log export and execution-path
deduplication remain outside this OBI API replay check.

The same Docker demo also exercises Postgres order inserts/reads and MySQL
payment inserts in the recording and replay flows. The order endpoint keeps its
airline `orderretrieve` call so the existing `HttpClient` operation remains
recorded; PostgreSQL supplies the response when the order row exists, with the
airline response as fallback. Other parsed TCP protocols can retain bounded raw
payloads but do not yet have Softprobe replay adapters.
