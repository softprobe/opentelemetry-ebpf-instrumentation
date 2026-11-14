#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="$(uname -m)"
GOARCH="amd64"
if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
  GOARCH="arm64"
fi

OBI_BIN="${OBI_BIN:-$ROOT_DIR/bin/obi-linux-$GOARCH}"
if [ ! -x "$OBI_BIN" ]; then
  mkdir -p "$ROOT_DIR/bin"
  echo "### Building obi-java-agent and Linux $GOARCH obi binary"
  (
    cd "$ROOT_DIR"
    docker build --platform "linux/$GOARCH" --output type=local,dest=pkg/internal/java/embedded --target=export -f javaagent.Dockerfile .
    GOOS=linux GOARCH="$GOARCH" go build -o "$OBI_BIN" ./cmd/obi
  )
fi

if [ "$(uname -s)" = "Linux" ]; then
  WORK_DIR="$(mktemp -d /tmp/obi-verify-java.XXXXXX)"
  trap 'rm -rf "$WORK_DIR"' EXIT
  chmod +x "$ROOT_DIR/scripts/verify-java-http/run.sh"
  sudo "$ROOT_DIR/scripts/verify-java-http/run.sh" "$WORK_DIR" "$OBI_BIN"
  exit 0
fi

chmod +x "$ROOT_DIR/scripts/verify-java-http/run.sh"
docker run --rm --privileged \
  -v "$ROOT_DIR/scripts/verify-java-http:/verify:ro" \
  -v "$OBI_BIN:/usr/local/bin/obi:ro" \
  eclipse-temurin:21-jdk-noble \
  /verify/run.sh /tmp/obi-verify /usr/local/bin/obi
