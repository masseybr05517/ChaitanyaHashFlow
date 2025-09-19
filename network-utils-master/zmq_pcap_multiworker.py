#!/usr/bin/env python3
# --------------------------------------------------------------------
#  flow_worker.py  —  ZeroMQ PULL worker(s) for flow records
#
#  Examples
#  --------
#  # single worker, print to stdout (exactly the old behaviour)
#  $ python3 flow_worker.py
#
#  # four workers, each appending to its own file flows_0.ndjson …
#  $ python3 flow_worker.py -n 4 -o flows.ndjson
#
#  # two workers to a custom endpoint
#  $ python3 flow_worker.py --endpoint tcp://192.168.1.10:6000 -n 2
# --------------------------------------------------------------------
import argparse
import json
import multiprocessing as mp
import os
import signal
import sys
import zmq
from typing import Optional


# ─────────────────────────────────────────────────────────────────────
def run_worker(wid: int, endpoint: str, out_path: Optional[str]) -> None:
    """Single worker process: connect PULL socket and stream NDJSON."""
    ctx = zmq.Context()
    sock = ctx.socket(zmq.PULL)
    sock.connect(endpoint)
    msg_cnt = 0

    # each worker gets its own file handle (safe for append)
    out = open(out_path, "a", encoding="utf‑8") if out_path else sys.stdout

    def shutdown(*_) -> None:
        print(f"\n[worker {wid}] shutting down …", file=sys.stderr, flush=True)
        sock.close(0)
        ctx.term()
        if out is not sys.stdout:
            out.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print(f"[worker {wid}] listening on {endpoint}", file=sys.stderr, flush=True)

    # ── main receive loop ────────────────────────────────────────────
    while True:
        raw = sock.recv()                     # blocks
        try:
            rec = json.loads(raw.decode())
        except json.JSONDecodeError as exc:
            print(f"[worker {wid}] JSON error: {exc}", file=sys.stderr, flush=True)
            continue

        # optional sentinel: {"STOP": true}
        if isinstance(rec, dict) and rec.get("STOP"):
            print(f"[worker {wid}] STOP received", file=sys.stderr, flush=True)
            break
        msg_cnt += 1
        print(f"{wid}: {msg_cnt}")
        # json.dump(rec, out)
        # out.write("\n")
        # out.flush()

    shutdown()


# ─────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Receive flow‑records over ZeroMQ; fan‑out to N workers."
    )
    parser.add_argument(
        "--endpoint",
        default="ipc:///tmp/flowpipe",
        help="ZMQ endpoint to connect (default: ipc:///tmp/flowpipe)",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Write NDJSON to FILE (for >1 worker the name becomes FILE_#.ndjson)",
    )
    parser.add_argument(
        "-n",
        "--num-workers",
        type=int,
        default=1,
        help="Number of worker processes to spawn (default: 1)",
    )
    args = parser.parse_args()

    # single‑process mode: keep behaviour identical to the old script
    if args.num_workers == 1:
        run_worker(0, args.endpoint, args.output)
        return

    # multi‑process mode
    mp.set_start_method("spawn")           # portable across OSes
    procs: list[mp.Process] = []

    for wid in range(args.num_workers):
        # if one output path is given, make per‑worker variants: flows_0.ndjson, …
        out_path = args.output
        if out_path and args.num_workers > 1:
            root, ext = os.path.splitext(out_path)
            out_path = f"{root}_{wid}{ext}" if ext else f"{root}_{wid}.ndjson"

        p = mp.Process(target=run_worker, args=(wid, args.endpoint, out_path))
        p.start()
        procs.append(p)

    # wait until all workers exit (Ctrl‑C propagates cleanly)
    try:
        for p in procs:
            p.join()
    except KeyboardInterrupt:
        print("\n[main] interrupt — terminating workers …", file=sys.stderr)
        for p in procs:
            p.terminate()
        for p in procs:
            p.join()


if __name__ == "__main__":
    main()
