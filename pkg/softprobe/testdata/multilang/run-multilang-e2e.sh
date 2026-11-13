#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OBI_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
COMPOSE_PROJECT="${COMPOSE_PROJECT:-sp-obi-multilang}"
SP_OBI_IMAGE="${SP_OBI_IMAGE:-sp-obi:multilang-test}"
SP_BIN="${SP_BIN:-sp}"
API_URL="${SP_API_URL:-http://127.0.0.1:28090}"
ARTIFACT_DIR="${VERIFY_ARTIFACT_DIR:-/tmp/verify-arex-obi-multilang}"
KEEP_STACK="${KEEP_STACK:-0}"

mkdir -p "${ARTIFACT_DIR}"
SP_XDG_ROOT="$(mktemp -d)"

COMPOSE=(docker compose -p "${COMPOSE_PROJECT}" -f "${SCRIPT_DIR}/docker-compose.yml")

cleanup() {
	rm -rf "${SP_XDG_ROOT}" >/dev/null 2>&1 || true
	if [ "${KEEP_STACK}" = "1" ]; then
		return 0
	fi
	SP_OBI_IMAGE="${SP_OBI_IMAGE}" "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

sp_cli() {
	XDG_CONFIG_HOME="${SP_XDG_ROOT}/config" \
	XDG_CACHE_HOME="${SP_XDG_ROOT}/cache" \
	XDG_DATA_HOME="${SP_XDG_ROOT}/data" \
	XDG_STATE_HOME="${SP_XDG_ROOT}/state" \
	SP_CONFIG="" \
	SP_API_URL="${API_URL}" \
	SP_TOKEN="${SP_AUTH_TOKEN:-}" \
	"${SP_BIN}" --api-url "${API_URL}" "$@"
}

if ! docker image inspect "${SP_OBI_IMAGE}" >/dev/null 2>&1; then
	echo "Building ${SP_OBI_IMAGE} from ${OBI_ROOT}..."
	docker buildx build --load -t "${SP_OBI_IMAGE}" -f "${SCRIPT_DIR}/obi/Dockerfile" "${OBI_ROOT}"
fi

echo "Starting ${COMPOSE_PROJECT} stack..."
SP_OBI_IMAGE="${SP_OBI_IMAGE}" "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
SP_OBI_IMAGE="${SP_OBI_IMAGE}" "${COMPOSE[@]}" up -d --build

wait_http_200() {
	local url="$1"
	local label="$2"
	local max_tries="${3:-60}"
	local i=0
	while [ "${i}" -lt "${max_tries}" ]; do
		local code
		code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 "${url}" 2>/dev/null || echo 000)"
		if [ "${code}" = "200" ]; then
			echo "READY: ${label} (${url})"
			return 0
		fi
		i=$((i + 1))
		sleep 2
	done
	echo "FAIL: ${label} failed to return 200 at ${url}" >&2
	return 1
}

wait_obi_attached() {
	local container="$1"
	local i=0
	while [ "${i}" -lt 60 ]; do
		if docker exec "${container}" sh -c "grep -qi ':46A8 ' /proc/net/tcp /proc/net/tcp6 2>/dev/null && grep -qi ':46A9 ' /proc/net/tcp /proc/net/tcp6 2>/dev/null" && \
			docker logs "${container}-obi" 2>&1 | grep -q "Attaching sock ops"; then
			if [ "${container}" != "multilang-node" ] || docker logs "${container}-obi" 2>&1 | grep -q "Script successfully injected"; then
				echo "READY: OBI dataplane and eBPF tracer attached in ${container}"
				return 0
			fi
		fi
		i=$((i + 1))
		sleep 1
	done
	echo "FAIL: OBI dataplane/tracer failed to attach in ${container}" >&2
	docker logs "${container}-obi" >&2 || true
	return 1
}

wait_http_200 "${API_URL}/vi/health" "multilang-backend" 90
wait_http_200 "http://127.0.0.1:28081/healthz" "multilang-py" 60
wait_http_200 "http://127.0.0.1:28082/healthz" "multilang-node" 60
wait_http_200 "http://127.0.0.1:28083/healthz" "multilang-go" 60

SP_AUTH_TOKEN=""
sp_cli config init --json >/dev/null
sp_cli config set-url "${API_URL}" --json >/dev/null
SP_AUTH_TOKEN="$(sp_cli auth login --guest --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["token"])')"

for app in multilang-py multilang-node multilang-go; do
	sp_cli config agent load --app "${app}" --json >/dev/null
done

wait_obi_attached "multilang-py"
wait_obi_attached "multilang-node"
wait_obi_attached "multilang-go"
sleep 2
RECORD_START_RFC3339="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sleep 1

echo "Sending 20 concurrent requests per service (60 total)..."
req_tmp="$(mktemp -d)"
pids=()

for id in $(seq 1 20); do
	(
		code="$(curl -sS -o "${req_tmp}/py-${id}.json" -w '%{http_code}' --max-time 15 "http://127.0.0.1:28081/api/py/quote/${id}")"
		[ "${code}" = "200" ] || { echo "py-${id} HTTP ${code}: $(cat "${req_tmp}/py-${id}.json" 2>/dev/null)" >&2; exit 1; }
	) &
	pids+=("$!")

	(
		code="$(curl -sS -o "${req_tmp}/node-${id}.json" -w '%{http_code}' --max-time 15 "http://127.0.0.1:28082/api/node/itinerary/${id}")"
		[ "${code}" = "200" ] || { echo "node-${id} HTTP ${code}: $(cat "${req_tmp}/node-${id}.json" 2>/dev/null)" >&2; exit 1; }
	) &
	pids+=("$!")

	(
		code="$(curl -sS -o "${req_tmp}/go-${id}.json" -w '%{http_code}' --max-time 15 "http://127.0.0.1:28083/api/go/checkout/${id}")"
		[ "${code}" = "200" ] || { echo "go-${id} HTTP ${code}: $(cat "${req_tmp}/go-${id}.json" 2>/dev/null)" >&2; exit 1; }
	) &
	pids+=("$!")
done

live_fail=0
for pid in "${pids[@]}"; do
	if ! wait "${pid}"; then
		live_fail=1
	fi
done
rm -rf "${req_tmp}"
if [ "${live_fail}" -ne 0 ]; then
	echo "FAIL: one or more live recording requests failed" >&2
	exit 1
fi

echo "Waiting for OTLP trace export and sp-backend indexing..."
wait_app_cases() {
	local app="$1"
	local min_cases="$2"
	local i=0
	while [ "${i}" -lt 30 ]; do
		local count
		count="$(sp_cli record case list --app "${app}" --limit 100 --json 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin).get("data") or {}
    items = d.get("items") or d.get("cases") or []
    print(len(items))
except Exception:
    print(0)
')"
		if [ "${count}" -ge "${min_cases}" ]; then
			echo "RECORDED: ${app} servlet_cases=${count}"
			return 0
		fi
		i=$((i + 1))
		sleep 2
	done
	echo "FAIL: ${app} did not index >= ${min_cases} Servlet cases in sp-backend" >&2
	return 1
}

wait_app_cases "multilang-py" 20
wait_app_cases "multilang-node" 20
wait_app_cases "multilang-go" 20

py_cases="$(sp_cli record case list --app multilang-py --limit 100 --json)"
node_cases="$(sp_cli record case list --app multilang-node --limit 100 --json)"
go_cases="$(sp_cli record case list --app multilang-go --limit 100 --json)"

py_ops="$(sp_cli record operation list --app multilang-py --json)"
node_ops="$(sp_cli record operation list --app multilang-node --json)"
go_ops="$(sp_cli record operation list --app multilang-go --json)"

PY_OPS="${py_ops}" NODE_OPS="${node_ops}" GO_OPS="${go_ops}" \
PY_CASES="${py_cases}" NODE_CASES="${node_cases}" GO_CASES="${go_cases}" python3 -c '
import json, os

def case_count(raw):
    d = json.loads(raw).get("data") or {}
    return len(d.get("items") or d.get("cases") or [])

apps = {
    "multilang-py": {
        "servletCaseCount": case_count(os.environ["PY_CASES"]),
        "operations": json.loads(os.environ["PY_OPS"]).get("data", {}),
    },
    "multilang-node": {
        "servletCaseCount": case_count(os.environ["NODE_CASES"]),
        "operations": json.loads(os.environ["NODE_OPS"]).get("data", {}),
    },
    "multilang-go": {
        "servletCaseCount": case_count(os.environ["GO_CASES"]),
        "operations": json.loads(os.environ["GO_OPS"]).get("data", {}),
    },
}
print(json.dumps({"apps": apps}, indent=2))
' | tee "${ARTIFACT_DIR}/multilang-ops.json"

python3 - "${ARTIFACT_DIR}/multilang-ops.json" <<'PY'
import json, sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    apps = json.load(fh)["apps"]

expected = {
    "multilang-py": {"Database", "Redis"},
    "multilang-node": {"Database"},
    "multilang-go": {"Database", "Redis"},
}
for app, req_cats in expected.items():
    if apps[app]["servletCaseCount"] < 20:
        raise SystemExit(f"FAIL: {app} servletCaseCount={apps[app]['servletCaseCount']} < 20")
    op_map = apps[app]["operations"].get("operationMap") or {}
    got = {k for k, v in op_map.items() if v}
    missing = req_cats - got
    if missing:
        raise SystemExit(f"FAIL: {app} missing recorded categories {sorted(missing)}; got={sorted(got)}")
    for db_op in op_map.get("Database", []):
        if db_op.startswith("default@"):
            raise SystemExit(f"FAIL: {app} recorded fallback default database in {db_op}")
print("PASS: all expected Servlet cases and Database/Redis operations recorded cleanly")
PY

echo "Stopping multilang-postgres, multilang-mysql, and multilang-redis..."
docker stop multilang-postgres multilang-mysql multilang-redis >/dev/null
docker inspect -f '{{.Name}} running={{.State.Running}}' multilang-postgres multilang-mysql multilang-redis | tee "${ARTIFACT_DIR}/offline-db-stopped.txt"

if grep -v 'running=false' "${ARTIFACT_DIR}/offline-db-stopped.txt" >/dev/null; then
	echo "FAIL: database container still running during offline replay" >&2
	exit 1
fi

run_offline_replay() {
	local app="$1"
	local target_env="$2"
	local run_out
	run_out="$(sp_cli replay run --app "${app}" --env "${target_env}" --from "${RECORD_START_RFC3339}" --selection last-n --limit 50 --enable-mock --watch --json)"
	local summary_json
	summary_json="$(RUN_OUT="${run_out}" python3 -c '
import json, os
last_doc = None
for line in os.environ["RUN_OUT"].splitlines():
    line = line.strip()
    if not line.startswith("{"):
        continue
    doc = json.loads(line)
    data = doc.get("data") or {}
    if "totalCaseCount" in data or (isinstance(data.get("body"), dict) and "totalCaseCount" in data["body"]):
        last_doc = doc
if last_doc is not None:
    print(json.dumps(last_doc))
')"
	if [ -z "${summary_json}" ]; then
		echo "FAIL: missing terminal replay statistics from replay run for ${app}: ${run_out}" >&2
		return 1
	fi
	printf '%s\n' "${summary_json}"
}

echo "Running offline replay against stopped database and cache containers..."
py_report="$(run_offline_replay "multilang-py" "http://multilang-py:8081")"
node_report="$(run_offline_replay "multilang-node" "http://multilang-node:8082")"
go_report="$(run_offline_replay "multilang-go" "http://multilang-go:8083")"

docker inspect -f '{{.Name}} running={{.State.Running}}' multilang-postgres multilang-mysql multilang-redis | tee "${ARTIFACT_DIR}/offline-db-stopped.txt"
if grep -v 'running=false' "${ARTIFACT_DIR}/offline-db-stopped.txt" >/dev/null; then
	echo "FAIL: database container restarted unexpectedly during replay" >&2
	exit 1
fi

PY_REP="${py_report}" NODE_REP="${node_report}" GO_REP="${go_report}" python3 -c '
import json, os

reports = {
    "multilang-py": json.loads(os.environ["PY_REP"]),
    "multilang-node": json.loads(os.environ["NODE_REP"]),
    "multilang-go": json.loads(os.environ["GO_REP"]),
}

def extract_counts(doc):
    data = doc.get("data") or {}
    body = data.get("body") if isinstance(data.get("body"), dict) else data
    item = body.get("planStatisticItem") if isinstance(body.get("planStatisticItem"), dict) else body
    total = int(item.get("totalCaseCount", body.get("totalCaseCount", 0)) or 0)
    passed = int(item.get("successCaseCount", item.get("passCaseCount", body.get("successCaseCount", 0))) or 0)
    failed = int(item.get("failCaseCount", body.get("failCaseCount", 0)) or 0)
    errored = int(item.get("errorCaseCount", body.get("errorCaseCount", 0)) or 0)
    plan_id = str(item.get("planId") or body.get("planId") or "")
    return plan_id, total, passed, failed, errored

sum_total = sum_pass = sum_fail = sum_err = 0
per_app = {}
for app, doc in reports.items():
    pid, t, p, f, e = extract_counts(doc)
    sum_total += t
    sum_pass += p
    sum_fail += f
    sum_err += e
    per_app[app] = {
        "planId": pid,
        "totalCaseCount": t,
        "passCaseCount": p,
        "failCaseCount": f,
        "errorCaseCount": e,
        "report": doc.get("data"),
    }

out = {
    "totalCaseCount": sum_total,
    "passCaseCount": sum_pass,
    "failCaseCount": sum_fail,
    "errorCaseCount": sum_err,
    "apps": per_app,
}
print(json.dumps(out, indent=2))
' | tee "${ARTIFACT_DIR}/multilang-replay.json"

if ! python3 - "${ARTIFACT_DIR}/multilang-replay.json" <<'PY'; then
import json, sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    summary = json.load(fh)

for app, stats in summary["apps"].items():
    if stats["totalCaseCount"] < 20:
        raise SystemExit(f"FAIL: {app} totalCaseCount={stats['totalCaseCount']} < 20")
    if stats["failCaseCount"] != 0 or stats["errorCaseCount"] != 0:
        raise SystemExit(
            f"FAIL: {app} planId={stats['planId']} failCaseCount={stats['failCaseCount']} errorCaseCount={stats['errorCaseCount']}"
        )

if summary["totalCaseCount"] < 60:
    raise SystemExit(f"FAIL: totalCaseCount={summary['totalCaseCount']} < 60")
if summary["failCaseCount"] != 0 or summary["errorCaseCount"] != 0:
    raise SystemExit(
        f"FAIL: aggregate failCaseCount={summary['failCaseCount']} errorCaseCount={summary['errorCaseCount']}"
    )
print(
    f"PASS: offline SQL and Redis replay succeeded across all 3 runtimes "
    f"(totalCaseCount={summary['totalCaseCount']}, passCaseCount={summary['passCaseCount']}, failCaseCount=0, errorCaseCount=0)"
)
PY
	echo "=== Diagnostic container logs ===" >&2
	for c in multilang-py multilang-py-obi multilang-node multilang-node-obi multilang-go multilang-go-obi; do
		echo "--- ${c} ---" >&2
		docker logs --tail=60 "${c}" >&2 || true
	done
	echo "=== Diagnostic MongoDB non-pass replay items ===" >&2
	docker exec multilang-mongodb mongosh --quiet -u myuser -p 1024.chaO --authenticationDatabase admin sp_storage_db --eval '
		const cols = db.getCollectionNames();
		for (const c of cols) {
			if (c.startsWith("RollingDatabaseMocker_") || c.startsWith("RollingRedisMocker_") || c === "ReplayMockDecision") {
				print("Mocker/Decision count " + c + ":", JSON.stringify(db.getCollection(c).aggregate([{$group: {_id: "$appId", count: {$sum: 1}}}]).toArray()));
			}
			if (c === "ReplayCompareResult" || c === "ReplayMockDecision") {
				const docs = db.getCollection(c).find({$or: [{diffResultCode: {$nin: [0, null]}}, {outcome: {$exists: true}}]}).limit(10).toArray();
				if (docs.length > 0) {
					print("Collection " + c + ":", JSON.stringify(docs, null, 2));
				}
			}
		}
	' >&2 || true
	exit 1
fi
