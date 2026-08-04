#!/bin/bash
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 0. Install mode
# 🧭 Default is the latest stable release binary. `--dev` installs the
# rolling development build of main (published by CI on every push);
# `--main` clones the latest main and compiles it locally (requires Rust).
INSTALL_MODE="release"
while [ $# -gt 0 ]; do
    case "$1" in
        --dev) INSTALL_MODE="dev" ;;
        --main) INSTALL_MODE="main" ;;
        -h|--help)
            echo "Usage: $0 [--dev|--main]"
            echo "  (default)  Install the latest stable release binary."
            echo "  --dev      Install the latest development build of main."
            echo "  --main     Clone main and compile it locally (requires Rust 1.97+)."
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Usage: $0 [--dev|--main]"
            exit 1
            ;;
    esac
    shift
done

echo -e "${GREEN}🦀 Pingclair Installer for Ubuntu / Debian / Fedora (${INSTALL_MODE} mode)${NC}"

# 1. Check Root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root (sudo bash install.sh)${NC}"
  exit 1
fi

# 2. Dependencies
# 🧭 Ubuntu/Debian is the first-class base, so apt is detected first; dnf is
# kept for Fedora. `libssl-dev` covers Ubuntu/Debian, while `libcap` on
# Fedora is what provides `setcap`.
echo "Installing runtime dependencies..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq openssl ca-certificates curl jq libssl-dev
else
    dnf install -y openssl ca-certificates curl jq libcap
fi

# 🔨 `--main` compiles BoringSSL from source, so it needs the same build
# packages the CI uses: cmake + a C++ compiler for BoringSSL, clang for
# bindgen, and git for boring-sys's vendored patch step.
if [ "$INSTALL_MODE" = "main" ]; then
    echo "Installing build dependencies..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y -qq cmake g++ perl pkg-config clang libclang-dev git
    else
        dnf install -y cmake gcc-c++ perl-interpreter pkgconf-pkg-config clang clang-devel git
    fi
fi

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

# 4. Download or build the binary
REPO="dorianverlaine/pingclair"

if [ "$INSTALL_MODE" = "main" ]; then
    # 🧭 Local build of the latest main; `--locked` pins the resolved
    # versions the tests ran against.
    if ! command -v cargo >/dev/null 2>&1; then
        echo -e "${RED}Error: --main builds from source and requires Rust 1.97 or newer.${NC}"
        echo "Install Rust first (https://rustup.rs) or use --dev for a prebuilt binary."
        exit 1
    fi
    RUST_VERSION=$(cargo --version | sed -n 's/^cargo \([0-9]*\)\.\([0-9]*\).*/\1.\2/p')
    RUST_MAJOR=${RUST_VERSION%%.*}
    RUST_MINOR=${RUST_VERSION#*.}
    RUST_MINOR=${RUST_MINOR%%.*}
    if [ "${RUST_MAJOR:-0}" -lt 1 ] || { [ "${RUST_MAJOR:-0}" -eq 1 ] && [ "${RUST_MINOR:-0}" -lt 97 ]; }; then
        echo -e "${RED}Error: --main requires Rust 1.97 or newer (found ${RUST_VERSION:-unknown}).${NC}"
        exit 1
    fi
    echo "Cloning latest main from $REPO..."
    BUILD_DIR=$(mktemp -d)
    git clone --depth 1 "https://github.com/$REPO.git" "$BUILD_DIR/pingclair"
    cd "$BUILD_DIR/pingclair"
    echo "Building the release binary (this takes a while)..."
    cargo build --release --locked
    cp target/release/pingclair /usr/local/bin/pingclair
    rm -rf "$BUILD_DIR"
    cd /
elif [ "$INSTALL_MODE" = "dev" ]; then
    # 🚀 Rolling development build of main, republished by CI on every push.
    echo "Fetching the latest development build of main..."
    TAR_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/tags/dev" | jq -r ".assets[] | select(.name == \"pingclair-linux-$ASSET_KEY-dev.tar.gz\") | .browser_download_url" | head -n 1)
    SUM_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/tags/dev" | jq -r ".assets[] | select(.name == \"SHA256SUMS-dev-$ASSET_KEY.txt\") | .browser_download_url" | head -n 1)
    if [ -z "$TAR_URL" ] || [ "$TAR_URL" == "null" ] || [ -z "$SUM_URL" ] || [ "$SUM_URL" == "null" ]; then
        echo -e "${RED}Error: no development build found for $ARCH in the rolling dev release.${NC}"
        echo "CI publishes it on every push to main. If it is missing, re-run the workflow"
        echo "or install from source with: sudo bash install.sh --main"
        exit 1
    fi
    echo "Downloading $TAR_URL..."
    curl -L -o "/tmp/pingclair-linux-$ASSET_KEY-dev.tar.gz" "$TAR_URL"
    curl -L -o "/tmp/SHA256SUMS-dev-$ASSET_KEY.txt" "$SUM_URL"
    # 🔐 Verify against the published checksum before installing.
    if command -v sha256sum >/dev/null 2>&1; then
        (cd /tmp && sha256sum -c "SHA256SUMS-dev-$ASSET_KEY.txt")
    else
        (cd /tmp && shasum -a 256 -c "SHA256SUMS-dev-$ASSET_KEY.txt")
    fi
    tar -xzf "/tmp/pingclair-linux-$ASSET_KEY-dev.tar.gz" -C /usr/local/bin/
    rm -f "/tmp/pingclair-linux-$ASSET_KEY-dev.tar.gz" "/tmp/SHA256SUMS-dev-$ASSET_KEY.txt"
    chmod +x /usr/local/bin/pingclair
else
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
# 🦀 Pingclair default configuration file
# Management commands: pc service <start|stop|reload|status>

:80 {
    # Welcome page
    file_server /var/lib/pingclair/html
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
# 📣 Matches scripts/pingclair.service — see the comment there.
Type=notify
NotifyAccess=main
User=pingclair
Group=pingclair
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
Environment="RUST_LOG=info"
ExecStartPre=/usr/local/bin/pingclair validate /etc/Pingclair/Pingclairfile
ExecStart=/usr/local/bin/pingclair run /etc/Pingclair/Pingclairfile
ExecReload=/bin/kill -HUP \$MAINPID
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
