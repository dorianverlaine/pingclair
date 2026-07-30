import socket, subprocess, sys, time, json, os, tempfile

PORT = 39181
UP   = 39182

cfg = {
  "global": {"http3": False},
  "servers": [{
    "listen": [f"127.0.0.1:{PORT}"],
    "routes": [
      {"path": "/ready", "handler": {"type": "respond", "status": 200, "body": "ready"}},
      {"path": "/echo", "handler": {"type": "reverse_proxy",
        "upstreams": [f"http://127.0.0.1:{UP}"],
        "load_balance": {"strategy": "round_robin"},
        "headers_up": {}, "headers_down": {}}}
    ]}]
}
cfgp = "/tmp/claude-501/smug/cfg.json"
open(cfgp, "w").write(json.dumps(cfg))

# upstream that reports exactly what it received
up = subprocess.Popen([sys.executable, "-c", f'''
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", {UP})); s.listen(16)
while True:
    c, _ = s.accept()
    try:
        c.settimeout(1.0)
        data = b""
        while b"\\r\\n\\r\\n" not in data:
            b = c.recv(65536)
            if not b: break
            data += b
        try:
            extra = c.recv(65536)
        except Exception:
            extra = b""
        body = (data + extra).decode("latin1")
        payload = body.encode("latin1")
        c.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: " + str(len(payload)).encode() + b"\\r\\nConnection: keep-alive\\r\\n\\r\\n" + payload)
    except Exception:
        pass
    finally:
        c.close()
'''])

env = dict(os.environ, PINGCLAIR_TLS_STORE="/tmp/claude-501/smug/tls")
srv = subprocess.Popen(["./target/debug/pingclair", "run", cfgp], env=env,
                       stdout=open("/tmp/claude-501/smug/srv.log","w"), stderr=subprocess.STDOUT)
time.sleep(2.5)

def raw(name, payload, read_all=True):
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=4)
        s.sendall(payload)
        s.settimeout(3)
        out = b""
        while True:
            try:
                b = s.recv(65536)
            except socket.timeout:
                break
            if not b: break
            out += b
            if not read_all: break
        s.close()
        first = out.split(b"\r\n")[0].decode("latin1") if out else "(no response)"
        n = out.count(b"HTTP/1.1 ")
        print(f"{name:<46} | {first:<32} | responses={n}")
        return out
    except Exception as e:
        print(f"{name:<46} | ERROR {e}")
        return b""

print(f"{'vector':<46} | {'status line':<32} | note")
print("-" * 100)

raw("baseline GET", b"GET /ready HTTP/1.1\r\nHost: a\r\n\r\n")
raw("CL + TE (CL.TE smuggle)",
    b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGARBAGE")
raw("TE + CL (TE.CL smuggle)",
    b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n")
raw("duplicate Content-Length differing",
    b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\nContent-Length: 5\r\n\r\nHELLO!")
raw("duplicate Content-Length identical",
    b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nHELLO")
raw("obs TE: 'chunked, identity'",
    b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n")
raw("obs TE: 'xchunked'",
    b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: xchunked\r\nContent-Length: 5\r\n\r\nHELLO")
raw("space before colon 'TE : chunked'",
    b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding : chunked\r\nContent-Length: 5\r\n\r\nHELLO")
raw("bare LF line endings",
    b"POST /echo HTTP/1.1\nHost: a\nContent-Length: 5\n\nHELLO")
raw("negative Content-Length",
    b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n")
raw("Content-Length with plus sign",
    b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: +5\r\n\r\nHELLO")
raw("Content-Length hex-ish '0x5'",
    b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 0x5\r\n\r\nHELLO")
raw("bad chunk size 'zz'",
    b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nAAAA\r\n0\r\n\r\n")
raw("header name with space 'X Y: v'",
    b"GET /ready HTTP/1.1\r\nHost: a\r\nX Y: v\r\n\r\n")
raw("CR-only line ending",
    b"GET /ready HTTP/1.1\rHost: a\r\r")

srv.terminate(); up.terminate()
try: srv.wait(5); up.wait(5)
except Exception: pass
