#!/usr/bin/env bash
# One-time provisioning: copy configs + payloads to the VPS, start the
# always-on shared backend. Run this once before run_remote_matrix.sh.
#
# Assumes: rust toolchain, nginx, caddy, wrk already installed; repo
# already cloned to /root/pingclair on the VPS (see chat history /
# benchmarks/README.md for the exact commands used).
set -euo pipefail
cd "$(dirname "$0")/.."
HOST="aqeonet-aliyun-shenzhen"

echo "==> Copying configs and payloads to VPS"
ssh "$HOST" "mkdir -p /root/bench/html /root/bench/configs"
scp configs/remote/backend/nginx.conf "$HOST:/root/bench/configs/backend.conf"
scp configs/remote/nginx/nginx.conf "$HOST:/root/bench/configs/nginx.conf"
scp configs/remote/caddy/Caddyfile "$HOST:/root/bench/configs/Caddyfile"
scp configs/remote/pingclair/Pingclairfile "$HOST:/root/bench/configs/Pingclairfile"
scp payloads/small.txt payloads/large.html "$HOST:/root/bench/html/"

echo "==> Building pingclair release binary on the VPS (if not already built)"
ssh "$HOST" "
  source \$HOME/.cargo/env
  cd /root/pingclair
  git pull --quiet
  test -f target/release/pingclair || cargo build --release --workspace
"

echo "==> Starting the always-on shared backend (port 9000)"
ssh "$HOST" "
  pkill -f 'nginx.*backend.conf' 2>/dev/null || true
  sleep 1
  nginx -c /root/bench/configs/backend.conf
  sleep 1
  curl -sf http://127.0.0.1:9000/ && echo ' <- backend OK'
"

echo "==> Provisioning done."
