#!/bin/bash
# =============================================================================
# Recon Ninja v2 — Dependency Installer
# =============================================================================
# One-shot script that installs ALL required tools and dependencies.
# Supports: apt (Debian/Ubuntu/Kali), dnf (Fedora/RHEL), pacman (Arch)
#
# Usage:
#   chmod +x install.sh && sudo ./install.sh
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

ok()   { echo -e "${GREEN}✅  $1${NC}"; }
warn() { echo -e "${YELLOW}⚠️  $1${NC}"; }
fail() { echo -e "${RED}❌  $1${NC}"; }
info() { echo -e "${CYAN}ℹ️  $1${NC}"; }
header() { echo -e "\n${BOLD}${CYAN}━━━ $1 ━━━${NC}\n"; }

# ---------------------------------------------------------------------------
# Track what was installed vs missing
# ---------------------------------------------------------------------------
INSTALLED=()
OPTIONAL_MISSING=()
REQUIRED_MISSING=()

# ---------------------------------------------------------------------------
# Detect package manager
# ---------------------------------------------------------------------------
detect_pkg_manager() {
    if command -v apt &>/dev/null; then
        echo "apt"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v pacman &>/dev/null; then
        echo "pacman"
    else
        echo "unknown"
    fi
}

PKG_MGR=$(detect_pkg_manager)
info "Detected package manager: ${PKG_MGR}"

if [[ "$PKG_MGR" == "unknown" ]]; then
    fail "No supported package manager found (apt/dnf/pacman). Exiting."
    exit 1
fi

# ---------------------------------------------------------------------------
# Package manager wrappers
# ---------------------------------------------------------------------------
pkg_update() {
    case "$PKG_MGR" in
        apt)   sudo apt update -y ;;
        dnf)   sudo dnf check-update -y || true ;;
        pacman) sudo pacman -Sy --noconfirm ;;
    esac
}

pkg_install() {
    case "$PKG_MGR" in
        apt)   sudo apt install -y "$@" ;;
        dnf)   sudo dnf install -y "$@" ;;
        pacman) sudo pacman -S --noconfirm --needed "$@" ;;
    esac
}

# ---------------------------------------------------------------------------
# 1. System package update
# ---------------------------------------------------------------------------
header "1. Updating package lists"
pkg_update

# ---------------------------------------------------------------------------
# 2. Install required apt packages
# ---------------------------------------------------------------------------
header "2. Installing system packages"

APT_PACKAGES=(
    nmap
    smbclient
    nikto
    whatweb
    sslscan
    onesixtyone
    snmp
    dnsrecon
    ldap-utils
    gobuster
    feroxbuster
    seclists
)

# Additional packages that are nice-to-have
OPTIONAL_PACKAGES=(
    crackmapexec
    ssh-audit
)

for pkg in "${APT_PACKAGES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null 2>&1 || command -v "$pkg" &>/dev/null; then
        ok "$pkg already installed"
        INSTALLED+=("$pkg (apt)")
    else
        info "Installing $pkg ..."
        if pkg_install "$pkg" 2>/dev/null; then
            ok "$pkg installed"
            INSTALLED+=("$pkg (apt)")
        else
            fail "$pkg — required, but installation failed"
            REQUIRED_MISSING+=("$pkg")
        fi
    fi
done

for pkg in "${OPTIONAL_PACKAGES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null 2>&1 || command -v "$pkg" &>/dev/null; then
        ok "$pkg already installed"
        INSTALLED+=("$pkg (apt)")
    else
        warn "$pkg — optional, could not install via apt"
        OPTIONAL_MISSING+=("$pkg")
    fi
done

# ---------------------------------------------------------------------------
# 3. Rust / Cargo / RustScan
# ---------------------------------------------------------------------------
header "3. Installing Rust + RustScan"

if command -v cargo &>/dev/null; then
    ok "Rust/Cargo already installed ($(cargo --version 2>/dev/null || echo 'unknown version'))"
    INSTALLED+=("rust/cargo")
else
    info "Installing Rust via rustup ..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    if command -v cargo &>/dev/null; then
        ok "Rust/Cargo installed"
        INSTALLED+=("rust/cargo")
    else
        fail "Rust/Cargo installation failed"
        REQUIRED_MISSING+=("rust/cargo")
    fi
fi

if command -v rustscan &>/dev/null; then
    ok "RustScan already installed"
    INSTALLED+=("rustscan")
else
    info "Installing RustScan via cargo ..."
    if cargo install rustscan 2>/dev/null; then
        ok "RustScan installed"
        INSTALLED+=("rustscan")
    else
        warn "RustScan cargo install failed — try manual install later"
        OPTIONAL_MISSING+=("rustscan")
    fi
fi

# ---------------------------------------------------------------------------
# 4. Go + Go tools
# ---------------------------------------------------------------------------
header "4. Installing Go + Go tools"

if command -v go &>/dev/null; then
    ok "Go already installed ($(go version 2>/dev/null))"
    INSTALLED+=("go")
else
    info "Installing Go ..."
    if pkg_install golang 2>/dev/null; then
        ok "Go installed via package manager"
        INSTALLED+=("go")
    elif command -v snap &>/dev/null; then
        sudo snap install go --classic
        if command -v go &>/dev/null; then
            ok "Go installed via snap"
            INSTALLED+=("go")
        else
            fail "Go installation failed"
            REQUIRED_MISSING+=("go")
        fi
    else
        # Fallback: download Go binary
        GO_VERSION="1.22.0"
        GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
        info "Downloading Go ${GO_VERSION} ..."
        wget -q "https://go.dev/dl/${GO_TARBALL}" -O "/tmp/${GO_TARBALL}"
        sudo tar -C /usr/local -xzf "/tmp/${GO_TARBALL}"
        rm -f "/tmp/${GO_TARBALL}"
        export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
        if command -v go &>/dev/null; then
            ok "Go ${GO_VERSION} installed manually"
            INSTALLED+=("go")
        else
            fail "Go installation failed"
            REQUIRED_MISSING+=("go")
        fi
    fi
fi

# Ensure GOPATH/bin is on PATH for this session
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"

GO_TOOLS=(
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/ropnop/kerbrute@latest"
    "github.com/sensepost/gowitness@latest"
    "github.com/owasp-amass/amass/v4/overrides/cmd/amass@latest"
    "github.com/ropnop/windapsearch-go@latest"
)

# Map of go module path → binary name (for checking if already installed)
GO_BINARIES=("ffuf" "nuclei" "subfinder" "httpx" "kerbrute" "gowitness" "amass" "windapsearch-go")

for i in "${!GO_TOOLS[@]}"; do
    tool="${GO_TOOLS[$i]}"
    binary="${GO_BINARIES[$i]}"
    if command -v "$binary" &>/dev/null; then
        ok "$binary already installed"
        INSTALLED+=("$binary (go)")
    else
        info "Installing $binary via go install ..."
        if go install "$tool" 2>/dev/null; then
            ok "$binary installed"
            INSTALLED+=("$binary (go)")
        else
            warn "$binary — go install failed"
            OPTIONAL_MISSING+=("$binary (go)")
        fi
    fi
done

# ---------------------------------------------------------------------------
# 5. Python dependencies
# ---------------------------------------------------------------------------
header "5. Installing Python dependencies"

PYTHON_TOOLS=(
    "theHarvester"
    "crackmapexec"
    "ssh-audit"
    "enum4linux-ng"
    "smbmap"
    "droopescan"
)

for tool in "${PYTHON_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null || pip show "$tool" &>/dev/null 2>&1; then
        ok "$tool already installed"
        INSTALLED+=("$tool (pip)")
    else
        info "Installing $tool via pip ..."
        if pip install "$tool" --break-system-packages 2>/dev/null; then
            ok "$tool installed"
            INSTALLED+=("$tool (pip)")
        else
            warn "$tool — pip install failed (may need manual install)"
            OPTIONAL_MISSING+=("$tool (pip)")
        fi
    fi
done

# Install the project itself (editable mode)
info "Installing recon-ninja in editable mode ..."
if pip install -e . --break-system-packages 2>/dev/null; then
    ok "recon-ninja installed (editable)"
    INSTALLED+=("recon-ninja (pip -e)")
else
    fail "recon-ninja pip install failed"
    REQUIRED_MISSING+=("recon-ninja")
fi

# ---------------------------------------------------------------------------
# 6. WPScan (Ruby gem)
# ---------------------------------------------------------------------------
header "6. Installing WPScan (Ruby gem)"

if command -v wpscan &>/dev/null; then
    ok "wpscan already installed"
    INSTALLED+=("wpscan (gem)")
else
    info "Installing wpscan via gem ..."
    if gem install wpscan 2>/dev/null; then
        ok "wpscan installed"
        INSTALLED+=("wpscan (gem)")
    else
        warn "wpscan gem install failed (requires Ruby dev headers)"
        OPTIONAL_MISSING+=("wpscan (gem)")
    fi
fi

# ---------------------------------------------------------------------------
# 7. SecLists
# ---------------------------------------------------------------------------
header "7. Ensuring SecLists are available"

SECLISTS_DIR="/usr/share/seclists"
if [[ -d "$SECLISTS_DIR" ]]; then
    ok "SecLists found at ${SECLISTS_DIR}"
    INSTALLED+=("seclists")
else
    info "SecLists not found — attempting to install ..."
    # Try apt first
    if pkg_install seclists 2>/dev/null; then
        ok "SecLists installed via package manager"
        INSTALLED+=("seclists")
    else
        info "Cloning SecLists from GitHub (this may take a while) ..."
        sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$SECLISTS_DIR" 2>/dev/null
        if [[ -d "$SECLISTS_DIR" ]]; then
            ok "SecLists cloned to ${SECLISTS_DIR}"
            INSTALLED+=("seclists")
        else
            fail "SecLists installation failed — some wordlists will be missing"
            REQUIRED_MISSING+=("seclists")
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 8. testssl.sh + joomscan (Git clones)
# ---------------------------------------------------------------------------
header "8. Installing testssl.sh + joomscan (Git clones)"

OPT_TOOLS_DIR="/opt/recon-tools"
sudo mkdir -p "$OPT_TOOLS_DIR"

# testssl.sh
if [[ -f "${OPT_TOOLS_DIR}/testssl.sh/testssl.sh" ]]; then
    ok "testssl.sh already present"
    INSTALLED+=("testssl.sh (git)")
else
    info "Cloning testssl.sh ..."
    sudo git clone --depth 1 https://github.com/drwetter/testssl.sh.git "${OPT_TOOLS_DIR}/testssl.sh" 2>/dev/null
    if [[ -f "${OPT_TOOLS_DIR}/testssl.sh/testssl.sh" ]]; then
        sudo chmod +x "${OPT_TOOLS_DIR}/testssl.sh/testssl.sh"
        ok "testssl.sh cloned"
        INSTALLED+=("testssl.sh (git)")
    else
        warn "testssl.sh clone failed"
        OPTIONAL_MISSING+=("testssl.sh")
    fi
fi

# joomscan
if [[ -f "${OPT_TOOLS_DIR}/joomscan/joomscan.pl" ]]; then
    ok "joomscan already present"
    INSTALLED+=("joomscan (git)")
else
    info "Cloning joomscan ..."
    sudo git clone --depth 1 https://github.com/OWASP/joomscan.git "${OPT_TOOLS_DIR}/joomscan" 2>/dev/null
    if [[ -f "${OPT_TOOLS_DIR}/joomscan/joomscan.pl" ]]; then
        sudo chmod +x "${OPT_TOOLS_DIR}/joomscan/joomscan.pl"
        ok "joomscan cloned"
        INSTALLED+=("joomscan (git)")
    else
        warn "joomscan clone failed"
        OPTIONAL_MISSING+=("joomscan")
    fi
fi

# ---------------------------------------------------------------------------
# 9. Add ~/go/bin to PATH in shell config
# ---------------------------------------------------------------------------
header "9. Configuring PATH"

GO_BIN="$HOME/go/bin"
PATH_LINE='export PATH="$HOME/go/bin:$PATH"'

configure_shell_rc() {
    local rc_file="$1"
    if [[ -f "$rc_file" ]]; then
        if ! rg -qF "$GO_BIN" "$rc_file" 2>/dev/null; then
            echo "" >> "$rc_file"
            echo "# Added by Recon Ninja installer" >> "$rc_file"
            echo "$PATH_LINE" >> "$rc_file"
            ok "Added ~/go/bin to ${rc_file}"
        else
            ok "~/go/bin already in ${rc_file}"
        fi
    fi
}

configure_shell_rc "$HOME/.bashrc"
configure_shell_rc "$HOME/.zshrc"

# Also add cargo env if newly installed
if [[ -f "$HOME/.cargo/env" ]]; then
    for rc_file in "$HOME/.bashrc" "$HOME/.zshrc"; do
        if [[ -f "$rc_file" ]] && ! rg -qF ".cargo/env" "$rc_file" 2>/dev/null; then
            echo '' >> "$rc_file"
            echo '# Added by Recon Ninja installer' >> "$rc_file"
            echo 'source "$HOME/.cargo/env"' >> "$rc_file"
            ok "Added cargo env to ${rc_file}"
        fi
    done
fi

# ---------------------------------------------------------------------------
# 10. Summary
# ---------------------------------------------------------------------------
header "Installation Summary"

echo -e "${BOLD}✅ Installed successfully (${#INSTALLED[@]}):${NC}"
for item in "${INSTALLED[@]}"; do
    echo -e "  ${GREEN}✅${NC}  $item"
done

if [[ ${#OPTIONAL_MISSING[@]} -gt 0 ]]; then
    echo ""
    echo -e "${BOLD}⚠️  Optional / failed but not critical (${#OPTIONAL_MISSING[@]}):${NC}"
    for item in "${OPTIONAL_MISSING[@]}"; do
        echo -e "  ${YELLOW}⚠️${NC}  $item"
    done
fi

if [[ ${#REQUIRED_MISSING[@]} -gt 0 ]]; then
    echo ""
    echo -e "${BOLD}❌ Required but failed (${#REQUIRED_MISSING[@]}):${NC}"
    for item in "${REQUIRED_MISSING[@]}"; do
        echo -e "  ${RED}❌${NC}  $item"
    done
fi

echo ""
if [[ ${#REQUIRED_MISSING[@]} -eq 0 ]]; then
    ok "All required dependencies installed successfully!"
    info "Run 'source ~/.bashrc' (or ~/.zshrc) to update your PATH, then: recon-ninja --help"
else
    fail "Some required dependencies failed. Please install them manually."
    exit 1
fi
