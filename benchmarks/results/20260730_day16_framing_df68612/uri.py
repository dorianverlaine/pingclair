import socket, subprocess, sys, time, json, os
PORT, UP = 39201, 39202
cfg={"global":{"http3":False},"servers":[{"listen":[f"127.0.0.1:{PORT}"],"routes":[
 {"path":"/static/*","handler":{"type":"file_server","root":"/tmp/claude-501/smug/root"}},
 {"path":"/api/*","handler":{"type":"reverse_proxy","upstreams":[f"http://127.0.0.1:{UP}"],
  "load_balance":{"strategy":"round_robin"},"headers_up":{},"headers_down":{}}},
 {"path":"/admin/*","handler":{"type":"respond","status":403,"body":"forbidden"}}]}]}
os.makedirs("/tmp/claude-501/smug/root/static", exist_ok=True)
open("/tmp/claude-501/smug/root/static/ok.txt","w").write("PUBLIC")
open("/tmp/claude-501/smug/secret.txt","w").write("SECRET-OUTSIDE-ROOT")
cfgp="/tmp/claude-501/smug/uri.json"; open(cfgp,"w").write(json.dumps(cfg))

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
        line=d.split(b"\\r\\n")[0]
        c.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: "+str(len(line)).encode()+b"\\r\\n\\r\\n"+line)
    except Exception: pass
    finally: c.close()
'''])
env=dict(os.environ, PINGCLAIR_TLS_STORE="/tmp/claude-501/smug/tls3")
srv=subprocess.Popen(["./target/debug/pingclair","run",cfgp],env=env,
    stdout=open("/tmp/claude-501/smug/srv3.log","w"),stderr=subprocess.STDOUT)
time.sleep(2.5)

def raw(name, line):
    try:
        s=socket.create_connection(("127.0.0.1",PORT),timeout=4)
        s.sendall(line.encode("latin1")+b" HTTP/1.1\r\nHost: a\r\n\r\n")
        s.settimeout(2.5); out=b""
        while True:
            try: b=s.recv(65536)
            except socket.timeout: break
            if not b: break
            out+=b
        s.close()
        head,_,body=out.partition(b"\r\n\r\n")
        status=head.split(b"\r\n")[0].decode("latin1")[9:].strip() if head else "(none)"
        peek=body.decode("latin1")[:48].replace("\r","").replace("\n"," ")
        print(f"{name:<44} | {status:<24} | {peek}")
    except Exception as e:
        print(f"{name:<44} | ERROR {e}")

print(f"{'vector':<44} | {'status':<24} | body/upstream-line")
print("-"*112)
raw("baseline static", "GET /static/ok.txt")
raw("dot-dot escape", "GET /static/../secret.txt")
raw("encoded dot-dot %2e%2e", "GET /static/%2e%2e/secret.txt")
raw("double-encoded %252e%252e", "GET /static/%252e%252e/secret.txt")
raw("encoded slash %2f in path", "GET /static/..%2fsecret.txt")
raw("backslash traversal", "GET /static/..\\secret.txt")
raw("admin bypass via dot-dot", "GET /api/../admin/x")
raw("admin bypass via %2e%2e", "GET /api/%2e%2e/admin/x")
raw("admin bypass via double slash", "GET //admin/x")
raw("admin bypass via /./", "GET /admin/./x")
raw("semicolon param", "GET /admin;/x")
raw("null byte %00", "GET /static/ok.txt%00.png")
raw("upstream sees encoded path", "GET /api/a%2fb")
raw("absolute-form request target", "GET http://evil.test/admin/x")
raw("tab in request line", "GET\t/admin/x")

srv.terminate(); up.terminate()
try: srv.wait(5); up.wait(5)
except Exception: pass
