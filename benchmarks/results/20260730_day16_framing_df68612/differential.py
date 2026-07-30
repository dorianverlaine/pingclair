import socket, subprocess, sys, time, json, os
PC = 39221
cfg={"global":{"http3":False},"servers":[{"listen":[f"127.0.0.1:{PC}"],"routes":[
 {"path":"/admin/*","handler":{"type":"respond","status":403,"body":"forbidden"}},
 {"path":"/api/*","handler":{"type":"respond","status":200,"body":"api"}},
 {"path":"/*","handler":{"type":"respond","status":200,"body":"root"}}]}]}
cfgp="/tmp/claude-501/diff/pc.json"; open(cfgp,"w").write(json.dumps(cfg))
env=dict(os.environ, PINGCLAIR_TLS_STORE="/tmp/claude-501/diff/tls")
srv=subprocess.Popen(["./target/debug/pingclair","run",cfgp],env=env,
    stdout=open("/tmp/claude-501/diff/pc.log","w"),stderr=subprocess.STDOUT)
time.sleep(2.5)

TARGETS=[("pingclair",PC),("nginx",18080),("caddy",18081)]
def probe(port, payload):
    try:
        s=socket.create_connection(("127.0.0.1",port),timeout=3); s.sendall(payload)
        s.settimeout(2); out=b""
        while True:
            try: b=s.recv(65536)
            except socket.timeout: break
            if not b: break
            out+=b
        s.close()
        if not out: return "(closed)"
        return out.split(b"\r\n")[0].decode("latin1")[9:].split(" ")[0]
    except Exception: return "ERR"

VECTORS=[
 ("路徑逃逸 /api/../admin/x", b"GET /api/../admin/x HTTP/1.1\r\nHost: a\r\n\r\n"),
 ("編碼逃逸 /api/%2e%2e/admin/x", b"GET /api/%2e%2e/admin/x HTTP/1.1\r\nHost: a\r\n\r\n"),
 ("/admin/./x", b"GET /admin/./x HTTP/1.1\r\nHost: a\r\n\r\n"),
 ("重複 Host", b"GET /api/x HTTP/1.1\r\nHost: a\r\nHost: evil\r\n\r\n"),
 ("缺 Host", b"GET /api/x HTTP/1.1\r\n\r\n"),
 ("Host 含空白", b"GET /api/x HTTP/1.1\r\nHost: a b\r\n\r\n"),
 ("Content-Length: +5", b"POST /api/x HTTP/1.1\r\nHost: a\r\nContent-Length: +5\r\n\r\nHELLO"),
 ("CL + TE", b"POST /api/x HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nXX"),
 ("重複 CL 值不同", b"POST /api/x HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\nContent-Length: 5\r\n\r\nHELLO!"),
 ("obs-fold", b"GET /api/x HTTP/1.1\r\nHost: a\r\nX-P: one\r\n  two\r\n\r\n"),
 ("bare LF", b"GET /api/x HTTP/1.1\nHost: a\n\n"),
 ("baseline /api/x", b"GET /api/x HTTP/1.1\r\nHost: a\r\n\r\n"),
]
print(f"{'vector':<30} | {'pingclair':<10} | {'nginx':<8} | {'caddy':<8} | 一致?")
print("-"*78)
for name,payload in VECTORS:
    r={n:probe(p,payload) for n,p in TARGETS}
    same = "✅" if r["pingclair"]==r["nginx"]==r["caddy"] else ("~" if r["pingclair"] in (r["nginx"],r["caddy"]) else "⚠️")
    print(f"{name:<30} | {r['pingclair']:<10} | {r['nginx']:<8} | {r['caddy']:<8} | {same}")
srv.terminate()
try: srv.wait(5)
except Exception: pass
