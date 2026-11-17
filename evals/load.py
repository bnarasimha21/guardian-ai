"""Latency of ``POST /api/check`` under concurrent load, against a running server.

    python evals/load.py --url http://localhost:8000 --key <api key> \
        --concurrency 1,8,32,64 --duration 20 --out load.json

It replays the call-phase records of the eval corpus (the same ones
``evals/latency.py`` times in process) over HTTP, with keep-alive connections,
at each concurrency level in turn, and reports per level: requests per second,
latency p50, p95 and p99 as the client sees it, and the mix of status codes.

It also times the same records through ``policy.engine.evaluate`` in this
process, so the difference between the two is what the HTTP path adds:
request parsing, authentication, the thread hop, the audit write and the
response.

What the numbers are not: they include this client's own cost and the network
between it and the server, which on one machine is the loopback interface.
Records the policy sends to a human (202) open approvals; once a session has
100 waiting, further ones are refused with 429. Both are counted, not hidden.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import statistics
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def load_records() -> list[dict]:
    records = []
    for path in sorted((ROOT / "evals" / "corpus").glob("*.jsonl")):
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("phase", "call") == "call" and "expand" not in rec:
                records.append(rec)
    return records


def pct(sorted_values: list[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    return sorted_values[max(0, min(len(sorted_values) - 1, int(len(sorted_values) * p) - 1))]


def summary(times_ms: list[float]) -> dict:
    times = sorted(times_ms)
    return {"count": len(times), "p50_ms": round(pct(times, 0.50), 3), "p95_ms": round(pct(times, 0.95), 3),
            "p99_ms": round(pct(times, 0.99), 3), "max_ms": round(times[-1], 3) if times else 0.0,
            "mean_ms": round(statistics.fmean(times), 3) if times else 0.0}


def in_process(records: list[dict], passes: int = 10) -> dict:
    """The same records through the engine in this process, no HTTP."""
    from backend.guardian.schema import ToolCall
    from backend.policy import engine
    from backend.policy.loader import PolicyStore

    loaded = PolicyStore(ROOT / "policies" / "default.yaml").get()
    times: list[float] = []
    for n in range(passes + 1):
        for rec in records:
            agent = rec.get("agent", "")
            call = ToolCall(name=rec["tool"], arguments=rec["arguments"], agent_id=agent, agent_name=agent)
            start = time.perf_counter()
            engine.evaluate(loaded, call, phase="call", block_threshold="high")
            if n:
                times.append((time.perf_counter() - start) * 1000)
    return summary(times)


def body_of(rec: dict) -> dict:
    out = {"tool": {"name": rec["tool"]}, "arguments": rec["arguments"]}
    if rec.get("agent"):
        out["agent"] = {"id": rec["agent"], "name": rec["agent"]}
    return out


class Connection:
    """One keep-alive HTTP/1.1 connection, with only what this test needs.

    A general client library costs more CPU per request than the server spends
    deciding, so at a few hundred requests a second the test would be measuring
    the client. This writes the request bytes and reads a Content-Length reply.
    """

    def __init__(self, host: str, port: int, head: bytes) -> None:
        self.host, self.port, self.head = host, port, head
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None

    async def open(self) -> None:
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)

    async def post(self, body: bytes) -> int:
        if self.writer is None:
            await self.open()
        self.writer.write(self.head + str(len(body)).encode() + b"\r\n\r\n" + body)
        await self.writer.drain()
        header = await self.reader.readuntil(b"\r\n\r\n")
        status = int(header[9:12])
        length = 0
        for line in header.split(b"\r\n")[1:]:
            if line[:15].lower() == b"content-length:":
                length = int(line[15:])
        if length:
            await self.reader.readexactly(length)
        return status

    def close(self) -> None:
        if self.writer is not None:
            self.writer.close()
            self.reader = self.writer = None


async def run_level(url: str, headers: dict, bodies: list[bytes], concurrency: int, duration: float,
                    timeout: float) -> dict:
    target = httpx.URL(url)
    if target.scheme != "http":
        raise SystemExit("the load test speaks plain HTTP: give an http:// URL")
    head = (f"POST /api/check HTTP/1.1\r\nHost: {target.host}\r\nContent-Type: application/json\r\n"
            + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "Content-Length: ").encode()
    times: list[float] = []
    statuses: dict[str, int] = {}
    errors: dict[str, int] = {}
    connections = [Connection(target.host, target.port or 80, head) for _ in range(concurrency)]
    # Open every connection and send one request on each, so connection setup
    # is not in the samples.
    await asyncio.gather(*(c.post(bodies[0]) for c in connections))
    stop_at = time.perf_counter() + duration

    async def worker(conn: Connection, offset: int) -> None:
        i = offset
        while time.perf_counter() < stop_at:
            body = bodies[i % len(bodies)]
            i += 1
            start = time.perf_counter()
            try:
                status = await asyncio.wait_for(conn.post(body), timeout)
            except Exception as exc:
                errors[type(exc).__name__] = errors.get(type(exc).__name__, 0) + 1
                conn.close()
                continue
            times.append((time.perf_counter() - start) * 1000)
            key = str(status)
            statuses[key] = statuses.get(key, 0) + 1

    started = time.perf_counter()
    await asyncio.gather(*(worker(c, n * 7) for n, c in enumerate(connections)))
    wall = time.perf_counter() - started
    for conn in connections:
        conn.close()
    out = summary(times)
    out.update(concurrency=concurrency, wall_s=round(wall, 2), requests_per_s=round(len(times) / wall, 1),
               statuses=dict(sorted(statuses.items())), errors=errors)
    return out


async def main_async(args) -> dict:
    records = load_records()
    bodies = [json.dumps(body_of(r)).encode() for r in records]
    headers = {"Authorization": f"Bearer {args.key}"} if args.key else {}
    async with httpx.AsyncClient(base_url=args.url, headers=headers, timeout=10) as client:
        ready = await client.get("/readyz")
    result = {
        "url": args.url, "records": len(records), "duration_s": args.duration,
        "client": f"Python {platform.python_version()}, {platform.machine()}",
        "arguments_json_bytes": {"median": statistics.median(len(json.dumps(r["arguments"])) for r in records),
                                 "max": max(len(json.dumps(r["arguments"])) for r in records)},
        "readyz": ready.json() if ready.headers.get("content-type", "").startswith("application/json") else None,
        "note": args.note,
        "in_process": in_process(records),
        "levels": [],
    }
    for concurrency in args.concurrency:
        level = await run_level(args.url, headers, bodies, concurrency, args.duration, args.timeout)
        result["levels"].append(level)
        print(f"concurrency {concurrency:>3}: {level['requests_per_s']:>8.1f} req/s  p50 {level['p50_ms']:>7.2f} ms  "
              f"p95 {level['p95_ms']:>7.2f} ms  p99 {level['p99_ms']:>7.2f} ms  statuses {level['statuses']}"
              + (f"  errors {level['errors']}" if level["errors"] else ""), flush=True)
        await asyncio.sleep(args.pause)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--key", default="", help="API key (GUARDIAN_API_KEYS); empty for an open server")
    parser.add_argument("--concurrency", default="1,8,32,64", type=lambda s: [int(x) for x in s.split(",") if x])
    parser.add_argument("--duration", type=float, default=20.0, help="seconds per concurrency level")
    parser.add_argument("--pause", type=float, default=2.0)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--note", default="", help="free text stored in the result, for example the deployment")
    parser.add_argument("--out", default="", help="write the result as JSON to this file")
    args = parser.parse_args()
    result = asyncio.run(main_async(args))
    base = result["in_process"]
    print(f"in process, same {result['records']} records: p50 {base['p50_ms']:.3f} ms  p95 {base['p95_ms']:.3f} ms  "
          f"p99 {base['p99_ms']:.3f} ms")
    first = result["levels"][0] if result["levels"] else None
    if first:
        print(f"HTTP path adds about {first['p50_ms'] - base['p50_ms']:.2f} ms at p50 at concurrency "
              f"{first['concurrency']}")
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2) + "\n")
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
