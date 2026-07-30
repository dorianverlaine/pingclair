import socket, subprocess, sys, time, json, os
PORT, UP = 39211, 39212
cfg={"global":{"http3":False},"servers":[{"listen":[f"127.0.0.1:{PORT}"],"routes":[
 {"path":"/*","handler":{"type":"reverse_proxy","upstreams":[f"http://127.0.0.1:{UP}"],
  "load_balance":{"strategy":"round_robin"},"headers_up":{},"headers_down":{}}}]}]}
cfgp="/tmp/claude-501/smug/hdr.json"; open(cfgp,"w").write(json.dumps(cfg))
up=subprocess.Popen([sys.executable,"-c",f'''
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",{UP})); s.listen(16)
while True:
    c,_=s.accept()
    try:
        c.settimeout(1.0); d=b""
        while b"\\r\\n\\r\\n" not in d:
            b=c.recv(65536)
            if not b: break
            d+=b
        c.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: "+str(len(d)).encode()+b"\\r\\n\\r\\n"+d)
    except Exception: pass
    finally: c.close()
'''])
env=dict(os.environ, PINGCLAIR_TLS_STORE="/tmp/claude-501/smug/tls4")
srv=subprocess.Popen(["./target/debug/pingclair","run",cfgp],env=env,
    stdout=open("/tmp/claude-501/smug/srv4.log","w"),stderr=subprocess.STDOUT)
time.sleep(2.5)
def raw(name, payload):
    try:
        s=socket.create_connection(("127.0.0.1",PORT),timeout=4); s.sendall(payload)
        s.settimeout(2.5); out=b""
        while True:
            try: b=s.recv(65536)
            except socket.timeout: break
            if not b: break
            out+=b
        s.close()
        head,_,body=out.partition(b"\r\n\r\n")
        st=head.split(b"\r\n")[0].decode("latin1")[9:].strip() if head else "(none)"
        up_saw=""
        for tag in (b"X-Probe", b"Host:", b"x-probe"):
            for ln in body.split(b"\r\n"):
                if ln.lower().startswith(tag.lower()):
                    up_saw = ln.decode("latin1")[:46]; break
            if up_saw: break
        print(f"{name:<44} | {st:<20} | 上游: {up_saw}")
    except Exception as e:
        print(f"{name:<44} | ERROR {e}")
print(f"{'vector':<44} | {'status':<20} | upstream")
print("-"*104)
raw("obs-fold (header continuation line)",
    b"GET / HTTP/1.1\r\nHost: a\r\nX-Probe: one\r\n  two\r\n\r\n")
raw("duplicate Host",
    b"GET / HTTP/1.1\r\nHost: a\r\nHost: evil\r\n\r\n")
raw("missing Host (HTTP/1.1)",
    b"GET / HTTP/1.1\r\nX-Probe: v\r\n\r\n")
raw("header value with bare CR",
    b"GET / HTTP/1.1\r\nHost: a\r\nX-Probe: a\rb\r\n\r\n")
raw("header value with NUL",
    b"GET / HTTP/1.1\r\nHost: a\r\nX-Probe: a\x00b\r\n\r\n")
raw("header name with colon prefix",
    b"GET / HTTP/1.1\r\nHost: a\r\n:evil: v\r\n\r\n")
raw("mixed-case header preserved?",
    b"GET / HTTP/1.1\r\nHost: a\r\nX-PrObE: MiXeD\r\n\r\n")
raw("empty header name",
    b"GET / HTTP/1.1\r\nHost: a\r\n: v\r\n\r\n")
raw("Host with whitespace",
    b"GET / HTTP/1.1\r\nHost: a b\r\n\r\n")
srv.terminate(); up.terminate()
try: srv.wait(5); up.wait(5)
except Exception: pass
