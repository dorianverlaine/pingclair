import socket, subprocess, sys, time, json, os

PORT, UP = 39191, 39192
cfg = {"global":{"http3":False},"servers":[{"listen":[f"127.0.0.1:{PORT}"],"routes":[
  {"path":"/echo","handler":{"type":"reverse_proxy","upstreams":[f"http://127.0.0.1:{UP}"],
   "load_balance":{"strategy":"round_robin"},"headers_up":{},"headers_down":{}}}]}]}
cfgp="/tmp/claude-501/smug/cfg2.json"; open(cfgp,"w").write(json.dumps(cfg))

up = subprocess.Popen([sys.executable,"-c",f'''
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",{UP})); s.listen(16)
while True:
    c,_=s.accept()
    try:
        c.settimeout(1.2); data=b""
        while b"\\r\\n\\r\\n" not in data:
            b=c.recv(65536)
            if not b: break
            data+=b
        try: data+=c.recv(65536)
        except Exception: pass
        p=data.decode("latin1").encode("latin1")
        c.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: "+str(len(p)).encode()+b"\\r\\n\\r\\n"+p)
    except Exception: pass
    finally: c.close()
'''])
env=dict(os.environ, PINGCLAIR_TLS_STORE="/tmp/claude-501/smug/tls2")
srv=subprocess.Popen(["./target/debug/pingclair","run",cfgp],env=env,
                     stdout=open("/tmp/claude-501/smug/srv2.log","w"),stderr=subprocess.STDOUT)
time.sleep(2.5)

def show(name,payload):
    s=socket.create_connection(("127.0.0.1",PORT),timeout=4); s.sendall(payload)
    s.settimeout(2.5); out=b""
    while True:
        try: b=s.recv(65536)
        except socket.timeout: break
        if not b: break
        out+=b
    s.close()
    print("="*78); print("### "+name)
    head,_,body = out.partition(b"\r\n\r\n")
    print("-- pingclair 回給客戶端 --"); print(head.decode("latin1")[:200])
    print("-- 上游實際收到 --")
    print(body.decode("latin1")[:600] if body else "(無)")

show("CL:6 + TE:chunked  (body: '0\\r\\n\\r\\nGARBAGE')",
     b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGARBAGE")
show("TE:chunked + CL:4",
     b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n")
show("Content-Length: +5",
     b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: +5\r\n\r\nHELLO")

srv.terminate(); up.terminate()
try: srv.wait(5); up.wait(5)
except Exception: pass
