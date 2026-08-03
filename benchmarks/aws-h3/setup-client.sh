#!/usr/bin/env bash
# 🖥️ Installs the load generators on the client host.
set -euo pipefail

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y wrk nghttp2-client python3-venv python3-pip docker.io curl
sudo systemctl enable --now docker
sudo usermod -aG docker ubuntu
python3 -m venv /home/ubuntu/h3-venv
/home/ubuntu/h3-venv/bin/pip install aioquic==1.3.0
sudo docker pull goodideal/nghttp2
