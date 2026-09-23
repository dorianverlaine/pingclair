#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

"""🔐 Compare TCP and QUIC certificate selection through a real Pingclairfile."""

import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import uuid


def main():
    """🧪 Exercise configured defaults and refusal without a default."""
    binary = os.environ["PINGCLAIR_BINARY"]
    curl = shutil.which("curl")
    if shutil.which("brew"):
        prefix = subprocess.check_output(["brew", "--prefix", "curl"], text=True).strip()
        curl = str(Path(prefix) / "bin/curl")
    assert curl and "HTTP3" in subprocess.check_output([curl, "--version"], text=True)
    with tempfile.TemporaryDirectory(prefix="pingclair-default-sni-") as directory:
        root = Path(directory)
        certificates = {}
        for name in ("first.test", "second.test"):
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(root / f"{name}.key"), "-out", str(root / f"{name}.pem"),
                "-days", "1", "-subj", f"/CN={name}", "-addext", f"subjectAltName=DNS:{name}",
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            certificates[name] = (root / f"{name}.pem").read_text().strip()

        for default, protected in ((None, False), ("second.test", False), ("first.test", False), ("first.test", True)):
            with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
                tcp.bind(("127.0.0.1", 0))
                port = tcp.getsockname()[1]
                udp.bind(("127.0.0.1", port))
            token = uuid.uuid4().hex
            option = f"default_sni {default}" if default else ""
            config = f"{{\n admin off\n {option}\n}}\n"
            for name in certificates:
                auth = " {\n client_auth {\n mode require\n }\n }" if protected and name == "first.test" else ""
                config += (
                    f"https://{name}:{port} {{\n"
                    f" tls {root / (name + '.pem')} {root / (name + '.key')}{auth}\n"
                    f' respond "{token}"\n}}\n'
                )
            path = root / "Pingclairfile"
            path.write_text(config)
            with (root / "server.log").open("w+") as log:
                process = subprocess.Popen(
                    [binary, "run", str(path)], stdout=log, stderr=log,
                    env={**os.environ, "PINGCLAIR_TLS_STORE": str(root / "store")},
                )
                try:
                    base = [curl, "-ksS", "--noproxy", "*", "--max-time", "5"]
                    url = f"https://second.test:{port}/"
                    resolve = ["--resolve", f"second.test:{port}:127.0.0.1"]
                    for _ in range(60):
                        assert process.poll() is None, "fixture exited before readiness"
                        ready = subprocess.run(base + ["--http1.1", *resolve, url], capture_output=True)
                        if ready.returncode == 0 and ready.stdout.decode() == token:
                            break
                        time.sleep(0.1)
                    else:
                        raise AssertionError("fixture never returned its unique readiness token")

                    for protocol in ("--http1.1", "--http3-only"):
                        # 🏷️ An IP URL omits SNI; Host only selects the HTTP route.
                        result = subprocess.run(base + [
                            protocol, "-H", "Host: first.test", "-o", os.devnull,
                            "-w", "%{http_code}\n%{certs}", f"https://127.0.0.1:{port}/",
                        ], capture_output=True, text=True)
                        if default is None:
                            assert result.returncode != 0 and result.returncode != 28, result.stderr
                            assert "BEGIN CERTIFICATE" not in result.stdout
                        else:
                            assert result.returncode == 0, result.stderr
                            expected_status = "421" if protected else "200"
                            assert result.stdout.splitlines()[0] == expected_status, result.stdout
                            leaf = re.search(
                                r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                                result.stdout, re.S,
                            )
                            assert leaf and leaf.group() == certificates[default], result.stdout
                        print(f"✅ {protocol}: default_sni={default!r}, protected={protected}", flush=True)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


if __name__ == "__main__":
    main()
