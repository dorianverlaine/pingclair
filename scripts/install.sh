#!/bin/bash
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🦀 Pingclair Installer for Ubuntu/Debian${NC}"

# 1. Check Root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root (sudo bash install.sh)${NC}"
  exit 1
fi

# 2. Dependencies
echo "Installing dependencies..."
apt-get update -qq
apt-get install -y -qq openssl ca-certificates curl jq libssl-dev

# 3. Detect Architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        ASSET_KEY="x86_64"
        ;;
    aarch64)
        ASSET_KEY="aarch64"
        ;;
    *)
        echo -e "${RED}Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac
echo "Detected architecture: $ARCH"

# 4. Download Binary
REPO="SinclairChao/pingclair"
echo "Fetching latest release from $REPO..."

LATEST_RELEASE_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | jq -r ".assets[] | select(.name | contains(\"$ASSET_KEY\") and contains(\"linux\")) | .browser_download_url" | head -n 1)

if [ -z "$LATEST_RELEASE_URL" ] || [ "$LATEST_RELEASE_URL" == "null" ]; then
    echo -e "${YELLOW}No binary found for $ARCH in latest release.${NC}"
    echo "Attempting cargo build fallback (requires Rust)..."
    if command -v cargo &> /dev/null; then
        cargo build --release
        cp target/release/pingclair /usr/local/bin/pingclair
    else
        echo -e "${RED}Error: Released binary not found and Cargo not installed.${NC}"
        echo "Please compile manually or create a GitHub Release with assets named 'pingclair-linux-$ASSET_KEY.tar.gz' or similar."
        exit 1
    fi
else
    echo "Downloading $LATEST_RELEASE_URL..."
    curl -L -o /tmp/pingclair.tar.gz "$LATEST_RELEASE_URL"
    tar -xzf /tmp/pingclair.tar.gz -C /usr/local/bin/
    chmod +x /usr/local/bin/pingclair
fi

# 5. Setup User
if ! id "pingclair" &>/dev/null; then
    echo "Creating system user 'pingclair'..."
    useradd -r -s /bin/false pingclair
fi

# 6. Capabilities (Bind Port 80/443)
echo "Setting capabilities..."
setcap cap_net_bind_service=+ep /usr/local/bin/pingclair

# 7. Directory Structure & Assets
echo "Configuring directories and assets..."
mkdir -p /etc/Pingclair
mkdir -p /var/lib/pingclair/html
mkdir -p /var/log/pingclair

# Download/Install Premium Assets
BASE_RAW_URL="https://raw.githubusercontent.com/$REPO/main"

echo "Fetching default landing page..."
curl -s -L -o /var/lib/pingclair/html/index.html "$BASE_RAW_URL/examples/public/index.html" || {
    echo "Fallback: Creating minimal landing page..."
    echo "<h1>Pingclair is Running!</h1>" > /var/lib/pingclair/html/index.html
}

echo "Fetching example configuration..."
curl -s -L -o /etc/Pingclair/Pingclairfile.example "$BASE_RAW_URL/examples/Pingclairfile.example"

# Default Config if missing
if [ ! -f /etc/Pingclair/Pingclairfile ]; then
    echo "Creating default Pingclairfile..."
    cat > /etc/Pingclair/Pingclairfile <<EOF
# 🦀 Pingclair 默认配置文件
# 管理命令: pc service <start|stop|reload|status>

server "default" {
    listen: "0.0.0.0:80";
    
    route {
        # 欢迎页面
        _ => {
            file_server "/var/lib/pingclair/html";
        }
    }
}
EOF
fi

chown -R pingclair:pingclair /var/lib/pingclair
chown -R pingclair:pingclair /var/log/pingclair
chown -R pingclair:pingclair /etc/Pingclair

# 8. Systemd
echo "Installing Systemd service..."
# Assuming script is run from repo or we verify file existence.
# If remote install, we should download the service file.
if [ -f "scripts/pingclair.service" ]; then
    cp scripts/pingclair.service /etc/systemd/system/
else
    # Fallback to creating it here if script run standalone
    cat > /etc/systemd/system/pingclair.service <<EOF
[Unit]
Description=Pingclair High-Performance Web Server
After=network-online.target

[Service]
Type=simple
User=pingclair
Group=pingclair
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
Environment="RUST_LOG=info"
ExecStartPre=/usr/local/bin/pingclair validate /etc/Pingclair/Pingclairfile
ExecStart=/usr/local/bin/pingclair run /etc/Pingclair/Pingclairfile
WorkingDirectory=/var/lib/pingclair
Restart=always
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
fi

# 9. Create Symlink pc
echo "Creating 'pc' symlink..."
ln -sf /usr/local/bin/pingclair /usr/local/bin/pc

systemctl daemon-reload
systemctl enable pingclair
systemctl restart pingclair

echo -e "${GREEN}✅ Installation Complete!${NC}"
echo -e "Use ${YELLOW}pc service status${NC} to check the service."
echo -e "Config: ${YELLOW}/etc/Pingclair/Pingclairfile${NC}"

