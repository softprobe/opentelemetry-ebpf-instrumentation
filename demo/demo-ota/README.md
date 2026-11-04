# OBI record/replay with demo-ota

This harness runs `travel-ota`, OBI ingress/dependency gateways, and the OBI
sidecar in Docker. The dependency gateway calls the hosted Cloudflare NDC worker
at `https://spair.softprobe.ai`; no local airline server is required. It uses
the existing backend OTLP receiver and `/api/storage/record/query` API without
changing backend code.

Start the existing Softprobe development backend if it is not running:

```bash
cd /Users/bill/src/arex
make compose-backend-up
```

Build the OBI executable and demo application artifact. For Apple Silicon
Docker Desktop use `GOARCH=arm64`; use `GOARCH=amd64` for x86-64 Docker hosts.

```bash
cd /Users/bill/src/arex/sp-obi
make compile GOARCH=arm64
mvn -f ../demo-ota/pom.xml -B -DskipTests package
```

Start all demo services in Docker. The dependency gateway defaults to `record`.
The ingress gateway exposes the OTA app on port `18080` and records the six API
entrypoints expected by `e2e/test_ota_recording_e2e.py`:

```bash
docker compose -f demo/demo-ota/docker-compose.yml up -d
```

The ingress gateway captures request and response payloads as legacy-compatible
`Servlet` recordings. The dependency gateway captures upstream traffic as
legacy-compatible `HttpClient` recordings. Both submit spans through OTLP. OBI
shares the app's process namespace, enables bounded payload capture, and sends
its traces directly to the backend's `POST /v1/traces` endpoint. The demo does
not attach `sp-agent-java`. OBI's optional Java runtime helper is enabled so
replay context propagates across the Java server and client spans.

For application-session capture experiments, use
[`obi-session-capture.yaml`](obi-session-capture.yaml). It emits HTTP metadata
for the selected Java process and keeps HTTP, SQL, and generic payload buffers
disabled. The current OBI route policies normalize or filter spans after the
HTTP request has been observed; they do not provide an early method/path gate
before body buffering. Keep these buffer sizes at zero until that gate is
implemented and verified on each supported runtime. The regular `obi.yaml`
captures HTTP traffic for the record/replay demo. The OTA app stores booking and
payment records in its embedded H2 database; OBI does not observe those
in-process database calls as PostgreSQL or MySQL wire traffic.

Record a flight search and keep the trace ID and request body for replay:

```bash
curl -sS http://127.0.0.1:18080/api/flights/search \
  -H 'content-type: application/json' \
  -H 'traceparent: 00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01' \
  -d '{"fromCity":"JFK","toCity":"LAX","departureDate":"2026-12-01","tripType":"ONE_WAY","passengerInfo":{"adults":1,"children":0,"infants":0},"cabinClass":"ECONOMY"}'
```

Switch the dependency gateway to replay mode and repeat the exact request:

```bash
docker compose -f demo/demo-ota/docker-compose.yml stop softprobe-gateway
SOFTPROBE_GATEWAY_MODE=replay docker compose -f demo/demo-ota/docker-compose.yml up -d --force-recreate softprobe-gateway
curl -sS http://127.0.0.1:18080/api/flights/search \
  -H 'content-type: application/json' \
  -H 'traceparent: 00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01' \
  -H 'tracestate: sp=mode:replay;tid:0102030405060708090a0b0c0d0e0f10;rid:ffeeddccbbaa99887766554433221100' \
  -H 'sp-schedule-replay: true' \
  -d '{"fromCity":"JFK","toCity":"LAX","departureDate":"2026-12-01","tripType":"ONE_WAY","passengerInfo":{"adults":1,"children":0,"infants":0},"cabinClass":"ECONOMY"}'
```

The ingress gateway records entrypoint requests as `Servlet` mockers. Configure
Softprobe replay plans to target `http://softprobe-ingress:15002`. Ingress
restores the recorded trace ID from replay `tracestate`, forwards it to
`travel-ota`, and writes the completed `Servlet` replay result to the existing
backend query API. OBI context propagation carries the replay trace to airline
calls; the dependency gateway queries the recorded `HttpClient` response by
trace ID and request key. When an HTTP client omits `traceparent`, the gateway
uses OBI's per-request context handoff. Booking and payment records are stored in
the app's embedded H2 database, initialized automatically with the app and
adding no database service to the deployment. Its in-memory contents last for
the lifetime of the app process. OBI captures the app and airline HTTP spans;
embedded database calls are not part of the HTTP record/replay path.
The replay path does not call Cloudflare. To record again, recreate the
dependency gateway with the default mode:

```bash
docker compose -f demo/demo-ota/docker-compose.yml stop softprobe-gateway
docker compose -f demo/demo-ota/docker-compose.yml up -d --force-recreate softprobe-gateway
```

The dependency gateway needs `BPF` and `SYS_ADMIN` capabilities to consume
OBI's pinned per-request context map when an HTTP client does not propagate
`traceparent`. The demo Compose service grants those capabilities and mounts
`/sys/fs/bpf` read-only.

Stop the demo without removing persistent backend data:

```bash
docker compose -f demo/demo-ota/docker-compose.yml down
```

Other supported OBI protocols still retain bounded raw request/response
payloads, but do not yet have Softprobe replay adapters. The OBI sidecar requires
Linux eBPF support. Docker Desktop's Linux VM must permit privileged eBPF
access.
