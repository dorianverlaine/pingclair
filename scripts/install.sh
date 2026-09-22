#!/bin/bash
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 💾 cargo decides where the binary lands; `./target` is only its default.
# `CARGO_TARGET_DIR` and a `[build] target-dir` in `.cargo/config.toml` both
# move it, and AGENTS.md asks developers to keep that cache outside the
# checkout — so every "copy the binary we just built" step has to ask cargo
# rather than re-derive the path. Under `set -e` a wrong path aborts the
# installer halfway through, with the service files already written.
release_binary() {
    cargo metadata --format-version 1 --no-deps | jq -r '.target_directory + "/release/pingclair"'
}

# 0. Install mode
# 🧭 Default is the latest stable release binary. `--main` clones the latest
# main and compiles it locally (requires Rust).
#
# 📌 A `--dev` mode used to install a rolling development build that CI
# republished on every push to main. It was removed with that workflow: a
# second prebuilt channel meant a second set of artifacts to verify, and
# `--main` already covers "give me what is on main right now".
INSTALL_MODE="release"
while [ $# -gt 0 ]; do
    case "$1" in
        --main) INSTALL_MODE="main" ;;
        -h|--help)
            echo "Usage: $0 [--main]"
            echo "  (default)  Install the latest stable release binary."
            echo "  --main     Clone main and compile it locally (requires Rust 1.98+)."
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Usage: $0 [--main]"
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
        echo -e "${RED}Error: --main builds from source and requires Rust 1.98 or newer.${NC}"
        echo "Install Rust first (https://rustup.rs), or install a released binary"
        echo "by running this script with no flag."
        exit 1
    fi
    # 🎯 The required minor is named once. It used to be written twice — `-lt 97`
    # in the test and `1.98` in the message — so the check passed a toolchain the
    # message promised to reject, and the build then failed deep inside
    # BoringSSL with nothing pointing back here.
    REQUIRED_RUST_MAJOR=1
    REQUIRED_RUST_MINOR=98
    RUST_VERSION=$(cargo --version | sed -n 's/^cargo \([0-9]*\)\.\([0-9]*\).*/\1.\2/p')
    RUST_MAJOR=${RUST_VERSION%%.*}
    RUST_MINOR=${RUST_VERSION#*.}
    RUST_MINOR=${RUST_MINOR%%.*}
    if [ "${RUST_MAJOR:-0}" -lt "${REQUIRED_RUST_MAJOR}" ] || \
       { [ "${RUST_MAJOR:-0}" -eq "${REQUIRED_RUST_MAJOR}" ] && [ "${RUST_MINOR:-0}" -lt "${REQUIRED_RUST_MINOR}" ]; }; then
        echo -e "${RED}Error: --main requires Rust ${REQUIRED_RUST_MAJOR}.${REQUIRED_RUST_MINOR} or newer (found ${RUST_VERSION:-unknown}).${NC}"
        exit 1
    fi
    echo "Cloning latest main from $REPO..."
    BUILD_DIR=$(mktemp -d)
    git clone --depth 1 "https://github.com/$REPO.git" "$BUILD_DIR/pingclair"
    cd "$BUILD_DIR/pingclair"
    echo "Building the release binary (this takes a while)..."
    cargo build --release --locked
    cp "$(release_binary)" /usr/local/bin/pingclair
    rm -rf "$BUILD_DIR"
    cd /
else
    echo "Fetching latest release from $REPO..."

    # 🧭 One fetch, not three: the release document names the tag and carries
    # every asset URL, and asking the API again for each of them invites the
    # anonymous rate limit to answer differently halfway through.
    LATEST_RELEASE=$(curl -s "https://api.github.com/repos/$REPO/releases/latest")
    LATEST_TAG=$(printf '%s' "$LATEST_RELEASE" | jq -r ".tag_name // empty")
    LATEST_RELEASE_URL=$(printf '%s' "$LATEST_RELEASE" | jq -r ".assets[] | select(.name | contains(\"$ASSET_KEY\") and contains(\"linux\")) | .browser_download_url" | head -n 1)
    LATEST_SUM_URL=$(printf '%s' "$LATEST_RELEASE" | jq -r ".assets[] | select(.name == \"SHA256SUMS-$ASSET_KEY.txt\") | .browser_download_url" | head -n 1)

    # 🚧 A release candidate is the latest release while 0.2.0 is being cut.
    # Say so at install time: the tag is the only thing that distinguishes it
    # from a final release once the binary is on the box.
    case "$LATEST_TAG" in
        *-*) echo -e "${YELLOW}Installing $LATEST_TAG — a release candidate, not a final release.${NC}" ;;
        ?*)  echo "Installing $LATEST_TAG..." ;;
    esac

    if [ -z "$LATEST_RELEASE_URL" ] || [ "$LATEST_RELEASE_URL" == "null" ]; then
        echo -e "${YELLOW}No binary found for $ARCH in latest release.${NC}"
        echo "Attempting cargo build fallback (requires Rust)..."
        if command -v cargo &> /dev/null; then
            cargo build --release
            cp "$(release_binary)" /usr/local/bin/pingclair
        else
            echo -e "${RED}Error: Released binary not found and Cargo not installed.${NC}"
            echo "Please compile manually or create a GitHub Release with assets named 'pingclair-linux-$ASSET_KEY.tar.gz' or similar."
            exit 1
        fi
    else
        echo "Downloading $LATEST_RELEASE_URL..."
        curl -L -o /tmp/pingclair.tar.gz "$LATEST_RELEASE_URL"
        # 🔐 Verify against the published checksum before unpacking anything
        # into /usr/local/bin. This runs as root from a piped script, so a
        # truncated or substituted download must stop here. A release with no
        # checksum file is refused rather than installed unverified.
        if [ -z "$LATEST_SUM_URL" ] || [ "$LATEST_SUM_URL" == "null" ]; then
            echo -e "${RED}Error: $LATEST_TAG publishes no SHA256SUMS-$ASSET_KEY.txt, so the download cannot be verified.${NC}"
            rm -f /tmp/pingclair.tar.gz
            exit 1
        fi
        TAR_NAME=$(basename "$LATEST_RELEASE_URL")
        mv /tmp/pingclair.tar.gz "/tmp/$TAR_NAME"
        curl -L -o "/tmp/SHA256SUMS-$ASSET_KEY.txt" "$LATEST_SUM_URL"
        if command -v sha256sum >/dev/null 2>&1; then
            (cd /tmp && sha256sum -c "SHA256SUMS-$ASSET_KEY.txt")
        else
            (cd /tmp && shasum -a 256 -c "SHA256SUMS-$ASSET_KEY.txt")
        fi
        tar -xzf "/tmp/$TAR_NAME" -C /usr/local/bin/
        rm -f "/tmp/$TAR_NAME" "/tmp/SHA256SUMS-$ASSET_KEY.txt"
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
# 🔐 The certificate store named by `scripts/pingclair.service`. It has to exist
# and be owned by the service user, because that unit sets
# `PINGCLAIR_TLS_STORE` here rather than letting the binary fall back to a
# `$HOME` that a system account does not have.
mkdir -p /var/lib/pingclair/certs

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
    # 🧭 This is a byte-for-byte copy of `scripts/pingclair.service`, reached
    # when the script runs without the repository beside it (the `curl | bash`
    # path). It used to be a *reduced* copy, and the two drifted: this one kept
    # `Restart=always` without `RestartPreventExitStatus=1`, so a configuration
    # the server refuses at startup was retried every five seconds instead of
    # leaving the unit failed and visible. `just repo-lint` compares this block
    # with the repository copy and fails when they differ, so edit one and the
    # gate asks for the other.
    # 🚫 The quoting around `EOF` is load-bearing: unquoted, the shell runs the
    # binary while writing this section and expands whatever it prints into the
    # unit file — 25 lines of `--help` output, once, until it was quoted.
    cat > /etc/systemd/system/pingclair.service <<'EOF'
[Unit]
Description=Pingclair High-Performance Web Server
Documentation=https://github.com/dorianverlaine/pingclair
After=network-online.target
Wants=network-online.target

[Service]
# 📣 `notify` rather than `simple`: with `simple`, systemd considers the unit
# started the instant the process is forked, so anything ordered `After=` races
# against the listeners actually being bound. Pingclair sends READY=1 only after
# every listener has been added, so `systemctl start` blocks until the proxy can
# really answer — and STOPPING=1 on shutdown, so `systemctl stop` knows the
# drain has begun rather than guessing from the process still being alive.
Type=notify
NotifyAccess=main
User=pingclair
Group=pingclair
# Allow binding ports < 1024
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Paths
Environment="RUST_LOG=info"
# 🔐 The certificate store must be named here, not left to the binary's
# default. Without it Pingclair resolves `$XDG_DATA_HOME/pingclair`, then
# `$HOME/.local/share/pingclair` — and the `pingclair` user is a system account
# with no home directory, so the service dies at startup with
# `Permission denied` before `RestartPreventExitStatus=1` leaves it dead. This
# is the same path `deployment/Dockerfile` sets, so both install paths persist
# certificates in one place.
Environment="PINGCLAIR_TLS_STORE=/var/lib/pingclair/certs"
# 🚫 Deliberately no `ExecStartPre=/usr/local/bin/pingclair validate …` here.
# It looks like the safe place for the check and it is the trap: systemd applies
# `RestartPreventExitStatus=` to the main process, not to a failing pre-command,
# so a configuration the compiler refuses was retried every five seconds instead
# of leaving the unit failed. The server compiles the file itself before it binds
# anything, and exits 1 when it refuses it — the exit code the restart policy
# below was written for. Measured on Ubuntu 24.04 (systemd 255): pre-command
# failure, `NRestarts` climbing with `is-active=activating`; server exit 1,
# `is-active=failed` with `NRestarts=0`.
ExecStart=/usr/local/bin/pingclair run /etc/Pingclair/Pingclairfile
# 🔔 SIGUSR1 is the reload signal. SIGHUP is dropped on purpose — it is the
# signal table Caddy uses — so the `kill -HUP` this unit used to send reported
# success and applied nothing at all. systemd can only see whether `kill`
# exited, never what the server then made of the file, so the reload's own
# result lands on this unit's status line instead: `systemctl status pingclair`
# reads `Serving (reloaded …)` or `Reload rejected: …` once the reload settles.
ExecReload=/bin/kill -USR1 $MAINPID
WorkingDirectory=/var/lib/pingclair

# Restart Policy
# 🛡️ Exit code 1 means failed startup (bad config, missing cert files, ...).
# Do not restart automatically in that case — the process will only fail
# again; an operator must fix the configuration first.
Restart=on-failure
RestartPreventExitStatus=1
RestartSec=5s

# Performance
LimitNOFILE=1048576
LimitNPROC=512

# Hardening
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true

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
