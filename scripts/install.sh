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

# 🔐 One digest, whichever sha256 tool the distribution ships.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
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
    # 🧊 releases.pingclair.com first. Its channel document names the tag, every
    # asset, and the sha256 of each one, and the host has no egress fee and a CDN
    # in front of it — which matters most to users far from GitHub. GitHub stays
    # the fallback and remains where releases are created.
    RELEASES_BASE_URL="${PINGCLAIR_RELEASES_BASE_URL:-https://releases.pingclair.com/pingclair}"
    TAR_NAME="pingclair-linux-$ASSET_KEY.tar.gz"
    RELEASE_SOURCE=""
    EXPECTED_SHA256=""
    LATEST_TAG=""
    LATEST_RELEASE_URL=""
    LATEST_SUM_URL=""

    CHANNEL_DOCUMENT=$(curl -fsSL --max-time 20 "$RELEASES_BASE_URL/channels/latest" 2>/dev/null || true)
    if [ -n "$CHANNEL_DOCUMENT" ]; then
        LATEST_TAG=$(printf '%s' "$CHANNEL_DOCUMENT" | jq -r ".tag_name // empty" 2>/dev/null || true)
        LATEST_RELEASE_URL=$(printf '%s' "$CHANNEL_DOCUMENT" | jq -r ".assets[] | select(.name == \"$TAR_NAME\") | .browser_download_url" 2>/dev/null | head -n 1)
        EXPECTED_SHA256=$(printf '%s' "$CHANNEL_DOCUMENT" | jq -r ".assets[] | select(.name == \"$TAR_NAME\") | .digest" 2>/dev/null | head -n 1 | sed 's/^sha256://')
        if [ -n "$LATEST_RELEASE_URL" ] && [ "$LATEST_RELEASE_URL" != "null" ] \
            && [ -n "$EXPECTED_SHA256" ] && [ "$EXPECTED_SHA256" != "null" ]; then
            RELEASE_SOURCE="releases.pingclair.com"
        fi
    fi

    if [ -z "$RELEASE_SOURCE" ]; then
        echo -e "${YELLOW}releases.pingclair.com did not answer with a release channel; falling back to GitHub.${NC}"
        echo "Fetching latest release from $REPO..."

        # 🧭 One fetch, not three: the release document names the tag and carries
        # every asset URL, and asking the API again for each of them invites the
        # anonymous rate limit to answer differently halfway through.
        LATEST_RELEASE=$(curl -s "https://api.github.com/repos/$REPO/releases/latest")
        LATEST_TAG=$(printf '%s' "$LATEST_RELEASE" | jq -r ".tag_name // empty")
        LATEST_RELEASE_URL=$(printf '%s' "$LATEST_RELEASE" | jq -r ".assets[] | select(.name | contains(\"$ASSET_KEY\") and contains(\"linux\")) | .browser_download_url" | head -n 1)
        LATEST_SUM_URL=$(printf '%s' "$LATEST_RELEASE" | jq -r ".assets[] | select(.name == \"SHA256SUMS-$ASSET_KEY.txt\") | .browser_download_url" | head -n 1)
        if [ -n "$LATEST_RELEASE_URL" ] && [ "$LATEST_RELEASE_URL" != "null" ]; then
            RELEASE_SOURCE="github.com"
        fi
    fi

    # 🚧 A release candidate is the latest release while 0.2.0 is being cut.
    # Say so at install time: the tag is the only thing that distinguishes it
    # from a final release once the binary is on the box.
    case "$LATEST_TAG" in
        *-*) echo -e "${YELLOW}Installing $LATEST_TAG — a release candidate, not a final release.${NC}" ;;
        ?*)  echo "Installing $LATEST_TAG..." ;;
    esac

    if [ -z "$RELEASE_SOURCE" ]; then
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
        echo "Downloading $LATEST_RELEASE_URL (from $RELEASE_SOURCE)..."
        curl -L -o /tmp/pingclair.tar.gz "$LATEST_RELEASE_URL"
        mv /tmp/pingclair.tar.gz "/tmp/$TAR_NAME"
        # 🔐 Verify before unpacking anything into /usr/local/bin: this runs as
        # root from a piped script, so a truncated or substituted download must
        # stop here. The channel document carries one digest per asset; a
        # release with no verifiable digest is refused rather than installed
        # unverified.
        if [ "$RELEASE_SOURCE" = "releases.pingclair.com" ]; then
            ACTUAL_SHA256="$(sha256_of "/tmp/$TAR_NAME")"
            if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
                echo -e "${RED}Error: $TAR_NAME does not match the digest in the release channel.${NC}"
                echo "  expected sha256:$EXPECTED_SHA256"
                echo "  got      sha256:$ACTUAL_SHA256"
                rm -f "/tmp/$TAR_NAME"
                exit 1
            fi
            echo "✅ sha256 matches the release channel document"
        else
            if [ -z "$LATEST_SUM_URL" ] || [ "$LATEST_SUM_URL" == "null" ]; then
                echo -e "${RED}Error: $LATEST_TAG publishes no SHA256SUMS-$ASSET_KEY.txt, so the download cannot be verified.${NC}"
                rm -f "/tmp/$TAR_NAME"
                exit 1
            fi
            curl -L -o "/tmp/SHA256SUMS-$ASSET_KEY.txt" "$LATEST_SUM_URL"
            if command -v sha256sum >/dev/null 2>&1; then
                (cd /tmp && sha256sum -c "SHA256SUMS-$ASSET_KEY.txt")
            else
                (cd /tmp && shasum -a 256 -c "SHA256SUMS-$ASSET_KEY.txt")
            fi
            rm -f "/tmp/SHA256SUMS-$ASSET_KEY.txt"
        fi
        tar -xzf "/tmp/$TAR_NAME" -C /usr/local/bin/
        rm -f "/tmp/$TAR_NAME"
        chmod +x /usr/local/bin/pingclair
    fi
fi

# 5. Setup User
if ! id "pingclair" &>/dev/null; then
    echo "Creating system user 'pingclair'..."
    # 🏠 A home the machine actually has. `useradd -r` records `/home/pingclair`
    # and creates nothing, so anything that resolves a store from `$HOME` — a
    # manual `sudo -u pingclair pingclair …`, most of all — was pointed at a
    # directory that does not exist. `/var/lib/pingclair` is the directory this
    # installer already owns for the service, so the account's home is that.
    # 📌 `-m` is deliberately absent: the next steps create the directory with
    # the ownership it needs, and a service account does not want `/etc/skel`.
    useradd -r -d /var/lib/pingclair -s /bin/false pingclair
else
    # 🔁 Upgrades: point an existing account at the same directory, which also
    # fixes installs made when the home field named a path that never existed.
    # Without `-m`, so no files move and nothing is copied over the store.
    current_home="$(getent passwd pingclair | cut -d: -f6)"
    if [ "$current_home" != "/var/lib/pingclair" ]; then
        echo "Pointing the 'pingclair' user's home at /var/lib/pingclair..."
        # 🔁 `usermod` refuses to touch an account that has running processes,
        # and on an upgrade the service *is* one of them:
        #   usermod: user pingclair is currently used by process 2954
        # So the service stops here and the restart at the end of this script
        # brings it back — the same outage an upgrade already has.
        systemctl stop pingclair >/dev/null 2>&1 || true
        usermod -d /var/lib/pingclair pingclair
    fi
fi

# 6. Capabilities (Bind Port 80/443)
echo "Setting capabilities..."
setcap cap_net_bind_service=+ep /usr/local/bin/pingclair

# 7. Directory Structure & Assets
echo "Configuring directories and assets..."
mkdir -p /etc/Pingclair
mkdir -p /var/lib/pingclair/html
mkdir -p /var/log/pingclair
# 🔐 The certificate store, at the path the binary resolves for the service
# account: `$XDG_DATA_HOME/pingclair`, then `$HOME/.local/share/pingclair`. The
# account's home is `/var/lib/pingclair`, so the unit needs no environment
# variable to name it and `pingclair environ`, the documentation and an operator
# all agree on one path.
store_dir="/var/lib/pingclair/.local/share/pingclair"
mkdir -p "$store_dir"

# 🚚 Installs made before this path was chosen keep their certificates: the
# store holds the ACME account key and every issued certificate, and re-issuing
# them runs into the certificate authority's rate limits, so the old directory
# is copied, verified, and only then removed.
previous_store="/var/lib/pingclair/certs"
if [ -d "$previous_store" ] && [ -n "$(ls -A "$previous_store" 2>/dev/null)" ]; then
    echo "Moving the certificate store to $store_dir..."
    cp -a "$previous_store/." "$store_dir/"
    if diff -r "$previous_store" "$store_dir" >/dev/null 2>&1; then
        rm -rf "$previous_store"
        echo "✅ Certificates moved; the old directory is gone."
    else
        echo -e "${RED}Error: the copy into $store_dir does not match $previous_store, so nothing was removed.${NC}"
        echo "Compare the two directories and remove $previous_store by hand once you are satisfied."
        exit 1
    fi
elif [ -d "$previous_store" ]; then
    # ␀ The old path exists and is empty: it is the directory the previous
    # installer created, and nothing was ever written to it.
    rmdir "$previous_store" 2>/dev/null || true
fi

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
# 🔐 No `PINGCLAIR_TLS_STORE` here on purpose. The service account's home is
# `/var/lib/pingclair`, so the binary resolves its store to
# `/var/lib/pingclair/.local/share/pingclair` — the directory the installer
# creates and migrates certificates into, the one the documentation names, and
# the one `pingclair environ` prints. Naming a different path here would be a
# second answer to a question that already has one.
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
