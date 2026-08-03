#!/usr/bin/env bash
# 🖥️ Installs Docker and pulls every server candidate image on the bench host.
set -euo pipefail

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io git curl ca-certificates
sudo systemctl enable --now docker
sudo usermod -aG docker ubuntu
mkdir -p /home/ubuntu/bench/www/proxy /home/ubuntu/bench/certs /home/ubuntu/bench/configs

sudo docker pull nginx:alpine
sudo docker pull caddy:2-alpine
sudo docker pull vicanso/pingap:latest
