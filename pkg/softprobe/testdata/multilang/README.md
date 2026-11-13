# Multi-Language SQL and Redis Offline Replay Suite

This fixture suite verifies in-process PostgreSQL v3, MySQL v10, and Redis RESP2 and RESP3 capture and offline replay in `sp-obi`. None of the application containers install an OpenTelemetry or Softprobe SDK.

## Architecture

Each runtime runs alongside an `sp-obi` sidecar sharing its PID and network namespaces on the isolated `sp-obi-multilang` Docker network.

| Service | Runtime and Drivers | Host Port | Protocols Exercised |
| --- | --- | --- | --- |
| `multilang-py` | Python FastAPI, `asyncpg`, `redis.asyncio` | `127.0.0.1:28081` | PostgreSQL Extended Query binary rows, Redis `GET`, `SET`, `MGET`, bulk nil |
| `multilang-node` | Node.js Express, `pg`, `mysql2/promise` | `127.0.0.1:28082` | PostgreSQL Extended Query text rows, MySQL `COM_STMT_PREPARE` and `COM_STMT_EXECUTE` |
| `multilang-go` | Go `net/http`, `pgxpool`, `go-sql-driver/mysql`, `go-redis/v9` | `127.0.0.1:28083` | PostgreSQL Extended Query, MySQL prepared binary rows, Redis RESP3 `HELLO 3`, `GET`, `HSET`, `HGETALL` |
| `multilang-backend` | `sp-backend:local` | `127.0.0.1:28090` | OTLP trace ingestion, mock lookup, and HTTP replay runner |

PostgreSQL, MySQL, Redis, and MongoDB run without host port bindings so the suite never collides with local developer stacks.

## Run the Suite

Make sure `sp-backend:local`, the `sp` CLI, and an `sp-obi` test image are available on the host.

```bash
chmod +x pkg/softprobe/testdata/multilang/run-multilang-e2e.sh
VERIFY_ARTIFACT_DIR=/tmp/verify-arex-obi-multilang \
  ./pkg/softprobe/testdata/multilang/run-multilang-e2e.sh
```

## What the Runner Proves

1. Live recording sends 20 concurrent requests per runtime, totaling 60 requests, through `sp-obi` against live `multilang-postgres`, `multilang-mysql`, and `multilang-redis` containers.
2. Recorded operations include `Servlet`, `Database`, and `Redis` categories in `multilang-ops.json`.
3. `docker stop multilang-postgres multilang-mysql multilang-redis` stops all three data stores and records `running=false` in `offline-db-stopped.txt`.
4. `sp replay run --enable-mock --watch` replays all 60 cases across pre-warmed pooled sockets and newly opened offline connections with zero failures and zero errors in `multilang-replay.json`.
