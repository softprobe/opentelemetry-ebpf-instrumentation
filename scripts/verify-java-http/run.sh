#!/usr/bin/env bash
set -euo pipefail

WORK_DIR="${1:-/tmp/obi-verify-java-http}"
OBI_BIN="${2:?usage: run.sh <work_dir> <obi_bin>}"

mkdir -p "$WORK_DIR"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OBI_PID=""
JAVA_PID=""
MOCK_PID=""
cleanup() {
  if [ -n "$OBI_PID" ]; then kill "$OBI_PID" >/dev/null 2>&1 || true; fi
  if [ -n "$JAVA_PID" ]; then kill "$JAVA_PID" >/dev/null 2>&1 || true; fi
  if [ -n "$MOCK_PID" ]; then kill "$MOCK_PID" >/dev/null 2>&1 || true; fi
  wait || true
}
trap cleanup EXIT

keytool -genkeypair -alias obi-test -keyalg RSA -keysize 2048 \
  -storetype PKCS12 -keystore "$WORK_DIR/keystore.p12" -storepass changeit \
  -keypass changeit -dname "CN=127.0.0.1" -validity 1 >/dev/null 2>&1

javac -d "$WORK_DIR" "$SCRIPT_DIR/MockServerAndSink.java" "$SCRIPT_DIR/VerifyJavaHttp.java"

java -cp "$WORK_DIR" MockServerAndSink "$WORK_DIR" "$WORK_DIR/keystore.p12" > "$WORK_DIR/mock.log" 2>&1 &
MOCK_PID=$!

for _ in $(seq 1 100); do
  if [ -s "$WORK_DIR/server_ports.env" ]; then break; fi
  sleep 0.1
done
[ -s "$WORK_DIR/server_ports.env" ] || { echo "Timed out waiting for MockServerAndSink ports" >&2; cat "$WORK_DIR/mock.log" >&2; exit 1; }
# shellcheck disable=SC1091
source "$WORK_DIR/server_ports.env"

java -cp "$WORK_DIR" VerifyJavaHttp "$WORK_DIR" "$HTTP_PORT" "$HTTPS_PORT" > "$WORK_DIR/java.log" 2>&1 &
JAVA_PID=$!

for _ in $(seq 1 100); do
  if [ -s "$WORK_DIR/client_port.env" ]; then break; fi
  sleep 0.1
done
[ -s "$WORK_DIR/client_port.env" ] || { echo "Timed out waiting for VerifyJavaHttp client_port.env" >&2; cat "$WORK_DIR/java.log" >&2; exit 1; }
# shellcheck disable=SC1091
source "$WORK_DIR/client_port.env"

cat > "$WORK_DIR/obi.yaml" << YAML
trace_printer: json
discovery:
  instrument:
    - open_ports: ${LISTEN_PORT}
ebpf:
  track_request_headers: true
javaagent:
  enabled: true
  debug: true
otel_traces_export:
  endpoint: http://127.0.0.1:${OTLP_PORT}
  batch_timeout: 500ms
YAML

"$OBI_BIN" --config="$WORK_DIR/obi.yaml" > "$WORK_DIR/obi.log" 2>&1 &
OBI_PID=$!

# Poll for Java agent initialization inside the target JVM (no blind sleep).
attached=0
for _ in $(seq 1 150); do
  if grep -q "Setting up instrumentations debugging" "$WORK_DIR/java.log" 2>/dev/null; then
    attached=1
    break
  fi
  sleep 0.2
done
[ "$attached" -eq 1 ] || { echo "Timed out waiting for OBI Java agent attach" >&2; cat "$WORK_DIR/obi.log" >&2; exit 1; }

touch "$WORK_DIR/ready.flag"

# Poll for BOTH real OTLP HTTP /v1/traces delivery and the HTTPS 400 HTTPClient span.
verified=0
for _ in $(seq 1 120); do
  if [ -s "$WORK_DIR/otlp.bytes" ] \
    && grep -qE "\"type\":\"HTTPClient\".*\"serverPort\":\"${HTTPS_PORT}\".*\"status\":\"400\".*\"url\":\"/ndc/v21.3/offerprice\"" "$WORK_DIR/obi.log"; then
    verified=1
    break
  fi
  sleep 0.2
done

touch "$WORK_DIR/done.flag"
wait "$JAVA_PID" || true
JAVA_PID=""

if [ "$verified" -ne 1 ]; then
  echo "Verification failed: missing OTLP export or HTTP/HTTPS 400 HTTPClient spans" >&2
  echo "--- java.log ---" >&2
  cat "$WORK_DIR/java.log" >&2 || true
  echo "--- obi.log (tail) ---" >&2
  tail -n 60 "$WORK_DIR/obi.log" >&2 || true
  exit 1
fi

OTLP_BYTES=$(cat "$WORK_DIR/otlp.bytes")
grep -q 'Successfully loaded native library in bootstrap classloader' "$WORK_DIR/java.log"
echo "verify-java-http: OK (otlp_bytes=${OTLP_BYTES}, http_port=${HTTP_PORT}, https_port=${HTTPS_PORT})"
