"""Decision latency: time ``policy.engine.evaluate`` over the call-phase corpus.

    python evals/latency.py            # 20 timed passes after one warm-up pass

In process, single thread, no network. It measures the detectors plus the
policy rules for one call and nothing else: no HTTP request, no MCP hop, no
approval wait and no model detector. Records built with ``expand`` (the
oversized payloads for the scan limit) are left out, so the figures describe
ordinary small calls.
"""

from __future__ import annotations

import json
import platform
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.guardian.schema import ToolCall  # noqa: E402
from backend.policy import engine  # noqa: E402
from backend.policy.loader import PolicyStore  # noqa: E402

PASSES = 20


def main() -> None:
    loaded = PolicyStore(ROOT / "policies" / "default.yaml").get()
    records = []
    for path in sorted((ROOT / "evals" / "corpus").glob("*.jsonl")):
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("phase", "call") == "call" and "expand" not in rec:
                records.append(rec)

    times: list[float] = []
    for n in range(PASSES + 1):
        for rec in records:
            agent = rec.get("agent", "")
            call = ToolCall(name=rec["tool"], arguments=rec["arguments"], agent_id=agent, agent_name=agent)
            start = time.perf_counter()
            engine.evaluate(loaded, call, phase="call", block_threshold="high")
            if n:  # the first pass is warm-up
                times.append((time.perf_counter() - start) * 1000)

    times.sort()
    sizes = [len(json.dumps(r["arguments"])) for r in records]

    def pct(p: float) -> float:
        return times[max(0, int(len(times) * p) - 1)]

    print(f"{len(records)} call-phase records, {PASSES} passes, Python {platform.python_version()}")
    print(f"arguments as JSON: median {statistics.median(sizes):.0f} bytes, largest {max(sizes)} bytes")
    print(f"evaluate(): p50 {pct(0.5):.2f} ms, p95 {pct(0.95):.2f} ms, p99 {pct(0.99):.2f} ms, max {times[-1]:.2f} ms")


if __name__ == "__main__":
    main()
