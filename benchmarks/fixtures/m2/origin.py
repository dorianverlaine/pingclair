#!/usr/bin/env python3
"""Controllable HTTP origin for the M2 guardrail matrix.

Every guardrail in M2 only engages when something upstream goes wrong, so the
matrix needs an origin whose failure mode can be changed from outside while
the proxy keeps running. Restarting a container to change behaviour would also
change its address, which is a different variable; writing a file is not.

Behaviour is read from `/state` on every request:

  /state/mode    ok | fail | slow | hang   how the main routes answer
  /state/health  up | down                 how /health answers

`fail` returns 503, `slow` sleeps past any sane first-byte timeout, and `hang`
accepts the request and never answers at all — the three shapes a real origin
breaks in, and the three the retry, breaker, and timeout paths must each tell
apart.

The name is echoed in the body so a response identifies which backend served
it, which is what makes load-balancer exclusion observable from the client.
"""

import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME = os.environ.get("ORIGIN_NAME", "origin")
STATE = os.environ.get("ORIGIN_STATE", "/state")


def read_state(key, default):
    try:
        with open(os.path.join(STATE, key), "r") as handle:
            return handle.read().strip() or default
    except OSError:
        return default


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        # The proxy's own log is the record under test; this would only add noise.
        pass

    def _send(self, status, body):
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        path = self.path.split("?")[0]

        if path.endswith("/health"):
            if read_state("health", "up") == "up":
                self._send(200, "healthy")
            else:
                self._send(503, "unhealthy")
            return

        # 🪪 Reports what the proxy actually forwarded, so client identity can
        # be asserted from the origin's point of view rather than inferred.
        if path.endswith("/echo"):
            lines = [f"{key.lower()}: {value}" for key, value in self.headers.items()]
            self._send(200, "\n".join(sorted(lines)))
            return

        mode = read_state("mode", "ok")
        if mode == "fail":
            self._send(503, f"{NAME}-unavailable")
        elif mode == "slow":
            time.sleep(30)
            self._send(200, NAME)
        elif mode == "hang":
            # Never answers. The connection stays open until the proxy's own
            # timer fires, which is the thing being measured.
            time.sleep(3600)
        else:
            self._send(200, NAME)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        mode = read_state("mode", "ok")
        if mode == "fail":
            self._send(503, f"{NAME}-unavailable")
        else:
            self._send(200, f"{NAME}:{len(body)}")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    os.makedirs(STATE, exist_ok=True)
    ThreadingHTTPServer(("0.0.0.0", port), Origin).serve_forever()
