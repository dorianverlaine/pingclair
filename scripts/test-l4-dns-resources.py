#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

"""🐧 Controlled DNS, reload and admission pressure against an exact Linux release binary."""

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import socket
import ssl
import struct
import time
import traceback
from datetime import datetime, timezone
from http.client import HTTPConnection


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def question(wire):
    offset = 12
    labels = []
    while wire[offset]:
        length = wire[offset]
        offset += 1
        labels.append(wire[offset:offset + length].decode("ascii"))
        offset += length
    offset += 1
    return ".".join(labels), wire[12:offset + 4]


class DNS(asyncio.DatagramProtocol):
    def __init__(self):
        self.queries = 0
        self.tcp = set()
        self.peak_tcp = 0
        self.names = set()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, wire, remote):
        name, query = question(wire)
        self.queries += 1
        self.names.add(name)
        assert query[-4:-2] == b"\x00\x01", "IPv4 policy issued a different query family"
        slow = name.startswith("slow-")
        header = struct.pack("!HHHHHH", int.from_bytes(wire[:2], "big"),
                             0x8380 if slow else 0x8180, 1, 0 if slow else 1, 0, 0)
        answer = b"" if slow else struct.pack("!HHHIH4s", 0xC00C, 1, 1, 30, 4,
                                              socket.inet_aton("127.0.0.1"))
        self.transport.sendto(header + query + answer, remote)

    async def accept(self, reader, writer):
        self.tcp.add(writer)
        self.peak_tcp = max(self.peak_tcp, len(self.tcp))
        try:
            length = int.from_bytes(await reader.readexactly(2), "big")
            await reader.readexactly(length)
            # 🧹 Truncated DNS keeps TCP pending until retirement or shutdown cancels it.
            await reader.read()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            self.tcp.discard(writer)
            writer.close()
            await writer.wait_closed()


async def echo(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except ConnectionError:
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def http(address, path, body=b"", content_type="text/plain"):
    def request():
        connection = HTTPConnection("127.0.0.1", address, timeout=10)
        method = "POST" if body or path == "/stop" else "GET"
        try:
            connection.request(method, path, body=body,
                               headers={"Content-Type": content_type, "Connection": "close"})
            response = connection.getresponse()
            payload = response.read()
            assert 200 <= response.status < 300, (response.status, payload)
            return payload.decode()
        finally:
            connection.close()
    return await asyncio.to_thread(request)


async def eventually(operation, limit=15):
    async with asyncio.timeout(limit):
        while True:
            try:
                if result := await operation():
                    return result
            except (OSError, AssertionError):
                pass
            await asyncio.sleep(0.05)


def value(text, name):
    return sum(float(line.rsplit(" ", 1)[1]) for line in text.splitlines()
               if line.startswith(name + "{"))


async def run(args, result):
    started = time.monotonic()
    result.update(commit=args.commit, binary=str(args.binary), kernel=platform.uname()._asdict(),
                  measured_at_utc=datetime.now(timezone.utc).isoformat(),
                  binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                  sessions_per_listener=args.sessions, reloads=args.reloads,
                  tls_preread=args.tls,
                  supplied_build_profile=args.profile)
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(max(soft, 4096), hard), hard))
    loop = asyncio.get_running_loop()
    dns = DNS()
    udp, _ = await loop.create_datagram_endpoint(lambda: dns, local_addr=("127.0.0.1", 0))
    dns_port = udp.get_extra_info("sockname")[1]
    dns_tcp = await asyncio.start_server(dns.accept, "127.0.0.1", dns_port)
    origin = await asyncio.start_server(echo, "127.0.0.1", 0)
    origin_port = origin.sockets[0].getsockname()[1]
    static, dynamic, admin, web = [port() for _ in range(4)]
    assert len({static, dynamic, admin, web, origin_port, dns_port}) == 6
    token = f"l4-resource-{os.getpid()}-{time.monotonic_ns()}"
    payload = b"x"
    if args.tls:
        outgoing = ssl.MemoryBIO()
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).wrap_bio(
            ssl.MemoryBIO(), outgoing, server_hostname="resource.test")
        try:
            tls.do_handshake()
        except ssl.SSLWantReadError:
            pass
        payload = outgoing.read()

    def config(generation=None):
        terminal = "Route(when: .tls())" if args.tls else "Fallback"
        def source(name):
            return (f'Proxy(dynamic: .a("{name}", port: {origin_port}, resolvers: '
                    f'["127.0.0.1:{dns_port}"], versions: .ipv4, valid: .seconds(1), '
                    'stale: .seconds(60), allowIP: ["127.0.0.1/32"]))')
        routes = "" if generation is None else "\n".join(
            f'Route(when: .from(["203.0.113.10/32"])) {{ {source(f"slow-{generation}-{i}.test")} }}'
            for i in range(16))
        return f'''Admin(listen: "127.0.0.1:{admin}")
Metrics(enabled: true)
Shutdown(grace: .seconds(5))
TCPListener(on: "127.0.0.1:{static}") {{ {terminal} {{ Proxy(to: "127.0.0.1:{origin_port}") }} }}
.limits(maxConnections: {args.sessions})
.timeouts(connect: .seconds(1), idle: .seconds(60))
TCPListener(on: "127.0.0.1:{dynamic}") {{
{routes}
{terminal} {{ {source("main.test")} }}
}}
.limits(maxConnections: {args.sessions})
.timeouts(connect: .seconds(1), idle: .seconds(60))
HTTPListener(on: "127.0.0.1:{web}") {{ Site(host: "*") {{
Route(when: .path(exact: "/ready")) {{ Respond(body: "{token}") }}
Fallback {{ ServeMetrics() }}
}} }}
'''

    samples = result["samples"] = []
    held = []
    process = None
    log = (args.results / "server.log").open("wb")
    initial = config()
    path = args.results / "config.pingclair"
    path.write_text(initial)
    try:
        env = dict(os.environ, PINGCLAIR_TLS_STORE=str(args.results / "tls"), RUST_LOG="info")
        process = await asyncio.create_subprocess_exec(str(args.binary), "run", str(path),
                    stdout=log, stderr=log, env=env, start_new_session=True)
        result["pid"] = process.pid

        async def ready():
            return await http(web, "/ready") == token

        async def pool_ready():
            return value(await http(web, "/metrics"), "l4_dns_pool_available") == 1

        await eventually(ready)
        await eventually(pool_ready)

        async def sample(phase):
            status = dict(line.split(":", 1) for line in Path(f"/proc/{process.pid}/status").read_text().splitlines())
            metrics = await http(web, "/metrics")
            item = dict(phase=phase, seconds=time.monotonic() - started,
                        rss_kib=int(status["VmRSS"].split()[0]),
                        threads=int(status["Threads"]),
                        descriptors=len(list(Path(f"/proc/{process.pid}/fd").iterdir())),
                        sessions=value(metrics, "l4_active_connections"),
                        admission_rejections=value(metrics, "l4_admission_rejections_total"),
                        dns_tcp=len(dns.tcp), dns_queries=dns.queries)
            samples.append(item)
            return item

        baseline = await sample("baseline")
        for endpoint in (static, dynamic):
            for _ in range(args.sessions):
                reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
                writer.write(payload)
                await writer.drain()
                assert await asyncio.wait_for(reader.readexactly(len(payload)), 3) == payload
                held.append((reader, writer))
        loaded = await sample("loaded")
        assert loaded["sessions"] == args.sessions * 2, loaded
        for generation in range(args.reloads):
            payload = config(generation)
            (args.results / f"reload-{generation}.pingclair").write_text(payload)
            await http(admin, "/load", payload.encode(), "text/pingclair")
            await asyncio.sleep(0.25)
            for endpoint in (static, dynamic):
                reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
                assert await asyncio.wait_for(reader.read(1), 2) == b""
                writer.close()
                await writer.wait_closed()
            for reader, writer in (held[0], held[-1]):
                writer.write(b"r")
                await writer.drain()
                assert await asyncio.wait_for(reader.readexactly(1), 3) == b"r"
            current = await sample(f"reload-{generation}")
            assert current["sessions"] == args.sessions * 2, current
            assert current["descriptors"] <= loaded["descriptors"] + 40, current
        for _, writer in held:
            writer.close()
        await asyncio.gather(*(writer.wait_closed() for _, writer in held))
        held.clear()
        await http(admin, "/load", initial.encode(), "text/pingclair")

        async def drained():
            return not dns.tcp and value(await http(web, "/metrics"), "l4_active_connections") == 0

        await eventually(drained)
        idle = await sample("drained")
        assert idle["descriptors"] <= baseline["descriptors"] + 8, (baseline, idle)
        assert idle["admission_rejections"] == args.reloads * 2, idle
        await http(admin, "/stop")
        assert await asyncio.wait_for(process.wait(), 10) == 0
        assert not dns.tcp
        assert dns.peak_tcp <= 8, dns.peak_tcp
        assert "resource.test" not in dns.names
        result.update(status="passed", peak_dns_tcp=dns.peak_tcp, seconds=time.monotonic() - started)
    finally:
        for _, writer in held:
            writer.close()
        if process and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 10)
            except asyncio.TimeoutError:
                # 🧹 Escalate only the child created by this run after its graceful window expires.
                process.kill()
                await process.wait()
        origin.close()
        dns_tcp.close()
        udp.close()
        await origin.wait_closed()
        await dns_tcp.wait_closed()
        log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--sessions", type=int, default=128)
    parser.add_argument("--reloads", type=int, default=12)
    parser.add_argument("--tls", action="store_true", help="Exercise complete ClientHello preread before relay.")
    parser.add_argument("--profile", default="unspecified; preserve build settings with the results",
                        help="Operator-supplied compiler/profile metadata for the provided release binary.")
    args = parser.parse_args()
    assert platform.system() == "Linux", "This drill requires Linux /proc."
    assert len(args.commit) == 40 and all(c in "0123456789abcdef" for c in args.commit)
    assert 1 <= args.sessions <= 1024 and 1 <= args.reloads <= 64
    args.results.mkdir(parents=True, exist_ok=False)
    args.binary = args.binary.resolve(strict=True)
    result = {"status": "failed"}
    try:
        asyncio.run(run(args, result))
    except BaseException:
        result["error"] = traceback.format_exc()
        raise
    finally:
        (args.results / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
