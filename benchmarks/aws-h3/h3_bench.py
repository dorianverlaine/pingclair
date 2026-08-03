#!/usr/bin/env python3
"""🛩️ Measure HTTP/3 request throughput with either reused or fresh QUIC connections."""

import argparse
import asyncio
import json
import ssl
import time
from collections import Counter

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration


class H3Client(QuicConnectionProtocol):
    """📨 Collects complete HTTP/3 responses without buffering across requests."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.pending = {}

    async def request(self, authority, path):
        stream_id = self._quic.get_next_available_stream_id()
        future = asyncio.get_running_loop().create_future()
        self.pending[stream_id] = {"future": future, "status": None, "body": bytearray()}
        self.http.send_headers(
            stream_id,
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", path.encode()),
                (b"user-agent", b"pingclair-h3-bench/1"),
            ],
            end_stream=True,
        )
        self.transmit()
        return await future

    def quic_event_received(self, event):
        for http_event in self.http.handle_event(event):
            state = self.pending.get(http_event.stream_id)
            if state is None:
                continue
            if isinstance(http_event, HeadersReceived):
                for key, value in http_event.headers:
                    if key == b":status":
                        state["status"] = int(value)
            elif isinstance(http_event, DataReceived):
                state["body"].extend(http_event.data)
            if getattr(http_event, "stream_ended", False):
                self.pending.pop(http_event.stream_id, None)
                if not state["future"].done():
                    state["future"].set_result((state["status"], bytes(state["body"])))


async def use_connection(args, request_count):
    configuration = QuicConfiguration(alpn_protocols=H3_ALPN, is_client=True)
    configuration.server_name = args.server_name
    configuration.verify_mode = ssl.CERT_NONE
    results = []
    async with connect(
        args.host,
        args.port,
        configuration=configuration,
        create_protocol=H3Client,
    ) as client:
        for _ in range(request_count):
            started = time.perf_counter()
            status, body = await asyncio.wait_for(
                client.request(f"{args.server_name}:{args.port}", args.path),
                timeout=args.timeout,
            )
            results.append((status, len(body), time.perf_counter() - started))
    return results


async def run_reuse(args):
    counts = [args.requests // args.concurrency] * args.concurrency
    for index in range(args.requests % args.concurrency):
        counts[index] += 1
    return sum(await asyncio.gather(*(use_connection(args, count) for count in counts)), [])


async def run_fresh(args):
    semaphore = asyncio.Semaphore(args.concurrency)

    async def once():
        async with semaphore:
            return (await use_connection(args, 1))[0]

    return await asyncio.gather(*(once() for _ in range(args.requests)))


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--server-name", default="bench.local")
    parser.add_argument("--path", default="/small.txt")
    parser.add_argument("--mode", choices=("reuse", "fresh"), required=True)
    parser.add_argument("--requests", type=int, required=True)
    parser.add_argument("--concurrency", type=int, required=True)
    parser.add_argument("--expect-bytes", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    started = time.perf_counter()
    results = await (run_reuse(args) if args.mode == "reuse" else run_fresh(args))
    elapsed = time.perf_counter() - started
    failures = Counter(
        f"status={status},bytes={size}"
        for status, size, _ in results
        if status != 200 or size != args.expect_bytes
    )
    latencies = sorted(latency for _, _, latency in results)

    def percentile(value):
        return latencies[min(len(latencies) - 1, round((len(latencies) - 1) * value))] * 1000

    print(
        json.dumps(
            {
                "mode": args.mode,
                "requests": len(results),
                "concurrency": args.concurrency,
                "elapsed_s": elapsed,
                "requests_per_s": len(results) / elapsed,
                "latency_ms_p50": percentile(0.50),
                "latency_ms_p95": percentile(0.95),
                "failures": sum(failures.values()),
                "failure_types": failures,
            },
            sort_keys=True,
        )
    )
    if failures:
        raise SystemExit(2)


if __name__ == "__main__":
    asyncio.run(main())
