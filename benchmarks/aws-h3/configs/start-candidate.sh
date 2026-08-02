#!/usr/bin/env bash
# 🚦 Starts the shared backend plus one benchmark candidate on host network.
set -euo pipefail

candidate="${1:?candidate required: pingclair|nginx|caddy|pingap}"
mode="${2:-static}"

case "${mode}" in
    static|proxy) ;;
    *) echo "mode must be static|proxy" >&2; exit 1 ;;
esac

sudo docker rm -f bench-backend bench-candidate >/dev/null 2>&1 || true

# 🌐 Shared backend: nginx serving the same payloads on :9000.
sudo docker run -d --name bench-backend --network host \
    --ulimit nofile=65535:65535 \
    -v /home/ubuntu/bench/www:/var/www/html:ro \
    -v /home/ubuntu/bench/configs/backend-nginx.conf:/etc/nginx/nginx.conf:ro \
    nginx:alpine >/dev/null

case "$candidate" in
    pingclair)
        if [[ "${mode}" == proxy ]]; then
            conf=config-pingclair-aws-proxy.json
        else
            conf=config-pingclair-aws.json
        fi
        sudo docker run -d --name bench-candidate --network host \
            --ulimit nofile=65535:65535 \
            -v /home/ubuntu/bench/www:/var/www/html:ro \
            -v /home/ubuntu/bench/certs/bench.crt:/tmp/bench.crt:ro \
            -v /home/ubuntu/bench/certs/bench.key:/tmp/bench.key:ro \
            -v "/home/ubuntu/bench/configs/${conf}":/etc/pingclair/config.json:ro \
            -e PINGCLAIR_TLS_STORE=/tmp/pingclair-store \
            pingclair:h3perf-aws run /etc/pingclair/config.json >/dev/null
        ;;
    nginx)
        if [[ "${mode}" == proxy ]]; then
            conf=nginx-aws-proxy.conf
        else
            conf=nginx-aws.conf
        fi
        sudo docker run -d --name bench-candidate --network host \
            --ulimit nofile=65535:65535 \
            -v /home/ubuntu/bench/www:/var/www/html:ro \
            -v /home/ubuntu/bench/certs/bench.crt:/tmp/bench.crt:ro \
            -v /home/ubuntu/bench/certs/bench.key:/tmp/bench.key:ro \
            -v "/home/ubuntu/bench/configs/${conf}":/etc/nginx/nginx.conf:ro \
            nginx:alpine >/dev/null
        ;;
    caddy)
        if [[ "${mode}" == proxy ]]; then
            conf=Caddyfile.aws.proxy
        else
            conf=Caddyfile.aws
        fi
        sudo docker run -d --name bench-candidate --network host \
            --ulimit nofile=65535:65535 \
            -v /home/ubuntu/bench/www:/var/www/html:ro \
            -v /home/ubuntu/bench/certs/bench.crt:/tmp/bench.crt:ro \
            -v /home/ubuntu/bench/certs/bench.key:/tmp/bench.key:ro \
            -v "/home/ubuntu/bench/configs/${conf}":/etc/caddy/Caddyfile:ro \
            caddy:2-alpine >/dev/null
        ;;
    pingap)
        sudo docker run -d --name bench-candidate --network host \
            --ulimit nofile=65535:65535 \
            -v /home/ubuntu/bench/www:/var/www/html:ro \
            -v /home/ubuntu/bench/certs/bench.crt:/tmp/bench.crt:ro \
            -v /home/ubuntu/bench/certs/bench.key:/tmp/bench.key:ro \
            -v /home/ubuntu/bench/configs/pingap.toml:/etc/pingap.toml:ro \
            vicanso/pingap:latest pingap --conf /etc/pingap.toml >/dev/null
        ;;
    *)
        echo "unknown candidate: ${candidate}" >&2
        exit 1
        ;;
esac

sleep 2
echo "started ${candidate}"
