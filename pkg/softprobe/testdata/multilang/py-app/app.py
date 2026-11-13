import asyncio
import json
import os
import signal
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import asyncpg
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException

PG_DSN = os.environ.get("PG_DSN", "postgresql://postgres:postgres@multilang-postgres:5432/traveldb")
REDIS_URL = os.environ.get("REDIS_URL", "redis://multilang-redis:6379/0")

_pg_pool: asyncpg.Pool | None = None
_redis_client: aioredis.Redis | None = None
_worker_loop: asyncio.AbstractEventLoop | None = None

app = FastAPI()


async def _worker_clients() -> tuple[asyncpg.Pool, aioredis.Redis]:
    global _pg_pool, _redis_client
    if _pg_pool is None:
        _pg_pool = await asyncpg.create_pool(
            dsn=PG_DSN,
            min_size=0,
            max_size=4,
            ssl=False,
        )
    if _redis_client is None:
        redis_pool = aioredis.BlockingConnectionPool.from_url(
            REDIS_URL,
            decode_responses=True,
            max_connections=4,
            timeout=15,
        )
        _redis_client = aioredis.Redis(connection_pool=redis_pool)
    return _pg_pool, _redis_client


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.get("/api/py/quote/{item_id}")
async def get_quote(item_id: int):
    pg_pool, redis_client = await _worker_clients()
    row = await pg_pool.fetchrow(
        "SELECT id, code, title, price_cents, in_stock, attrs::text AS attrs_json "
        "FROM catalog_items WHERE id = $1 AND in_stock = $2",
        item_id,
        True,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="item not found")

    miss_key = f"py:miss:{item_id}"
    quote_key = f"py:quote:{item_id}"
    quote_val = f"{row['code']}:{row['price_cents']}"

    missed = await redis_client.get(miss_key)
    await redis_client.set(quote_key, quote_val)
    cached = await redis_client.get(quote_key)
    multi = await redis_client.mget(quote_key, miss_key)

    return {
        "service": "multilang-py",
        "id": int(row["id"]),
        "code": row["code"],
        "title": row["title"],
        "price_cents": int(row["price_cents"]),
        "in_stock": bool(row["in_stock"]),
        "attrs": json.loads(row["attrs_json"]),
        "cache_miss_was_null": missed is None,
        "cached": cached,
        "mget": multi,
    }


async def _invoke_asgi(
    method: str,
    raw_target: str,
    headers: list[tuple[bytes, bytes]],
    body: bytes,
) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
    parsed = urllib.parse.urlsplit(raw_target)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": urllib.parse.unquote(parsed.path or "/"),
        "raw_path": (parsed.path or "/").encode("latin-1"),
        "query_string": parsed.query.encode("latin-1"),
        "headers": headers,
        "client": ("127.0.0.1", 0),
        "server": ("0.0.0.0", 8081),
    }

    sent_req = False
    status_code = 500
    resp_headers: list[tuple[bytes, bytes]] = []
    resp_chunks: list[bytes] = []

    async def receive():
        nonlocal sent_req
        if not sent_req:
            sent_req = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        nonlocal status_code, resp_headers
        msg_type = message["type"]
        if msg_type == "http.response.start":
            status_code = int(message["status"])
            resp_headers = list(message.get("headers", []))
        elif msg_type == "http.response.body":
            chunk = message.get("body", b"")
            if chunk:
                resp_chunks.append(chunk)

    await app(scope, receive, send)
    return status_code, resp_headers, b"".join(resp_chunks)


class SequentialASGIHTTPServer(HTTPServer):
    allow_reuse_address = True
    request_queue_size = 128


class ASGIRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        return

    def _handle_all(self):
        global _worker_loop
        if _worker_loop is None or _worker_loop.is_closed():
            _worker_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(_worker_loop)

        content_len = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(content_len) if content_len > 0 else b""
        raw_headers = [
            (k.lower().encode("latin-1"), v.encode("latin-1"))
            for k, v in self.headers.items()
        ]

        try:
            status_code, resp_headers, resp_body = _worker_loop.run_until_complete(
                _invoke_asgi(self.command, self.path, raw_headers, body)
            )
        except Exception as exc:
            status_code = 500
            resp_headers = [(b"content-type", b"application/json")]
            resp_body = json.dumps({"error": str(exc)}).encode("utf-8")

        self.send_response(status_code)
        sent_cl = False
        for hk, hv in resp_headers:
            key_str = hk.decode("latin-1")
            if key_str.lower() == "content-length":
                sent_cl = True
            if key_str.lower() in ("date", "server", "connection", "transfer-encoding"):
                continue
            self.send_header(key_str, hv.decode("latin-1"))
        if not sent_cl:
            self.send_header("Content-Length", str(len(resp_body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if resp_body:
            self.wfile.write(resp_body)
        self.close_connection = True

    do_GET = _handle_all
    do_POST = _handle_all
    do_PUT = _handle_all
    do_DELETE = _handle_all


def main() -> None:
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    port = int(os.environ.get("PORT", "8081"))
    srv = SequentialASGIHTTPServer(("0.0.0.0", port), ASGIRequestHandler)
    srv.serve_forever()


if __name__ == "__main__":
    main()
