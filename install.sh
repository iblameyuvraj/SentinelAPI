#!/usr/bin/env bash
# ==============================================================================
# 🛡️ SentinelAPI — Autonomous Installer & Zsh Environment Setup
#
# One-Line Installation:
#   curl -fsSL https://raw.githubusercontent.com/iblameyuvraj/SentinelAPI/main/install.sh | bash
#   or
#   curl -fsSL https://raw.githubusercontent.com/iblameyuvraj/SentinelAPI/main/install.sh | zsh
# ==============================================================================

set -euo pipefail

# ── Color Definitions ─────────────────────────────────────────────────────────
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    MAGENTA='\033[0;35m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    DIM='\033[2m'
    RESET='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    MAGENTA=''
    CYAN=''
    BOLD=''
    DIM=''
    RESET=''
fi

# ── Status Logging Helpers ───────────────────────────────────────────────────
info() {
    printf "${CYAN}[i]${RESET} %s\n" "$*"
}

success() {
    printf "${GREEN}[✓]${RESET} %s\n" "$*"
}

warn() {
    printf "${YELLOW}[!]${RESET} %s\n" "$*"
}

error() {
    printf "${RED}[✖] ERROR:${RESET} %b\n" "$*" >&2
}

fatal() {
    error "$@"
    exit 1
}

# ── Banner ────────────────────────────────────────────────────────────────────
print_banner() {
    printf "${CYAN}${BOLD}"
    cat << 'EOF'
   ____             _   _            _    ____ ___ 
  / ___|  ___ _ __ | |_(_)_ __   ___| |  / ___|_ _|
  \___ \ / _ \ '_ \| __| | '_ \ / _ \ | | |  | | 
   ___) |  __/ | | | |_| | | | |  __/ | | |__| | 
  |____/ \___|_| |_|\__|_|_| |_|\___|_|  \____|___|
EOF
    printf "${RESET}"
    printf "${MAGENTA}${BOLD}  AI-Powered Zero-Trust API Security Testing & Pentesting Engine${RESET}\n"
    printf "${DIM}  Automated Installer & Shell Integrator • AmiHacks 2026${RESET}\n\n"
}

# ── Resolve Working & Target Directories ──────────────────────────────────────
CURRENT_DIR="$PWD"
IS_LOCAL_REPO=false

if [ -f "$CURRENT_DIR/pyproject.toml" ] && [ -d "$CURRENT_DIR/sentinelapi" ]; then
    IS_LOCAL_REPO=true
fi

# If SENTINEL_HOME is not explicitly passed by user:
if [ -z "${SENTINEL_HOME:-}" ]; then
    if [ "$IS_LOCAL_REPO" = true ]; then
        SENTINEL_HOME="$CURRENT_DIR"
    else
        SENTINEL_HOME="$HOME/.sentinel"
    fi
fi

SENTINEL_REPO="${SENTINEL_REPO:-https://github.com/iblameyuvraj/SentinelAPI.git}"
SENTINEL_BRANCH="${SENTINEL_BRANCH:-main}"
LOCAL_BIN="$HOME/.local/bin"

# ── Preflight Checks ──────────────────────────────────────────────────────────
check_dependencies() {
    info "Verifying system requirements and dependencies..."

    # Check OS
    OS="$(uname -s)"
    case "$OS" in
        Darwin*)
            ARCH="$(uname -m)"
            success "Detected macOS ($ARCH)"
            ;;
        Linux*)
            ARCH="$(uname -m)"
            success "Detected Linux ($ARCH)"
            ;;
        *)
            warn "Operating system '$OS' detected. SentinelAPI officially supports macOS and Linux."
            ;;
    esac

    # Check Git
    if command -v git >/dev/null 2>&1; then
        success "Git detected ($(git --version | head -n1))"
    else
        fatal "Git is required but was not found. Please install git:\n  macOS:         xcode-select --install\n  Debian/Ubuntu: sudo apt update && sudo apt install -y git\n  Fedora:        sudo dnf install -y git\n  Arch:          sudo pacman -S git"
    fi

    # Check Python (>= 3.9)
    PYTHON_BIN=""
    for candidate in python3.13 python3.12 python3.11 python3.10 python3.9 python3 python; do
        if command -v "$candidate" >/dev/null 2>&1; then
            if "$candidate" -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" 2>/dev/null; then
                PYTHON_BIN="$(command -v "$candidate")"
                break
            fi
        fi
    done

    if [ -z "$PYTHON_BIN" ]; then
        fatal "Python 3.9+ is required but was not found.\n  macOS:         brew install python@3.11\n  Debian/Ubuntu: sudo apt update && sudo apt install -y python3 python3-venv python3-pip\n  Fedora:        sudo dnf install -y python3 python3-pip\n  Arch:          sudo pacman -S python python-pip"
    fi

    PY_VER="$("$PYTHON_BIN" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')")"
    success "Python detected: $PYTHON_BIN (v$PY_VER)"

    # Verify python venv module is installed
    if ! "$PYTHON_BIN" -c "import venv" 2>/dev/null; then
        fatal "Python 'venv' module is missing.\nOn Debian/Ubuntu, please install it via:\n  sudo apt update && sudo apt install -y python3-venv"
    fi
}

# ── Source Acquisition ────────────────────────────────────────────────────────
setup_source_files() {
    if [ "$IS_LOCAL_REPO" = true ] && [ "$CURRENT_DIR" = "$SENTINEL_HOME" ]; then
        info "Configuring existing local SentinelAPI repository at $SENTINEL_HOME"
    elif [ "$IS_LOCAL_REPO" = true ] && [ "$CURRENT_DIR" != "$SENTINEL_HOME" ]; then
        info "Running installer from local clone: $CURRENT_DIR"
        info "Syncing repository files to $SENTINEL_HOME..."
        mkdir -p "$SENTINEL_HOME"
        if command -v rsync >/dev/null 2>&1; then
            rsync -a --delete \
                --exclude '.venv' \
                --exclude '__pycache__' \
                --exclude '*.pyc' \
                --exclude '.git' \
                "$CURRENT_DIR/" "$SENTINEL_HOME/"
        else
            cp -R "$CURRENT_DIR/"* "$SENTINEL_HOME/" 2>/dev/null || true
            cp "$CURRENT_DIR/.env"* "$SENTINEL_HOME/" 2>/dev/null || true
        fi
        success "Synchronized files to $SENTINEL_HOME"
    else
        # Running via curl / remote installation
        if [ -d "$SENTINEL_HOME/.git" ]; then
            info "Existing SentinelAPI git repository found at $SENTINEL_HOME"
            info "Pulling latest updates from origin/$SENTINEL_BRANCH..."
            git -C "$SENTINEL_HOME" fetch origin "$SENTINEL_BRANCH" --quiet || true
            git -C "$SENTINEL_HOME" checkout "$SENTINEL_BRANCH" --quiet || true
            git -C "$SENTINEL_HOME" pull --rebase origin "$SENTINEL_BRANCH" --quiet || true
            success "Repository updated to latest version"
        elif [ -d "$SENTINEL_HOME" ] && [ -f "$SENTINEL_HOME/pyproject.toml" ]; then
            info "SentinelAPI directory already exists at $SENTINEL_HOME"
        else
            info "Cloning SentinelAPI ($SENTINEL_BRANCH) into $SENTINEL_HOME..."
            mkdir -p "$(dirname "$SENTINEL_HOME")"
            git clone --depth 1 -b "$SENTINEL_BRANCH" "$SENTINEL_REPO" "$SENTINEL_HOME" --quiet
            success "Cloned repository successfully into $SENTINEL_HOME"
        fi
    fi
}

# ── Python Environment Setup ──────────────────────────────────────────────────
setup_virtualenv() {
    info "Setting up isolated virtual environment in $SENTINEL_HOME/.venv..."

    if [ ! -d "$SENTINEL_HOME/.venv" ]; then
        "$PYTHON_BIN" -m venv "$SENTINEL_HOME/.venv"
        success "Created Python virtual environment"
    else
        success "Existing virtual environment verified"
    fi

    VENV_PIP="$SENTINEL_HOME/.venv/bin/pip"
    VENV_PYTHON="$SENTINEL_HOME/.venv/bin/python"

    info "Installing SentinelAPI dependencies and core engine (this may take a few moments)..."
    "$VENV_PYTHON" -m pip install --upgrade pip setuptools wheel --quiet
    "$VENV_PIP" install -r "$SENTINEL_HOME/requirements.txt" --quiet
    "$VENV_PIP" install -e "$SENTINEL_HOME" --quiet
    success "Dependencies installed successfully"

    # Setup .env if missing
    if [ ! -f "$SENTINEL_HOME/.env" ] && [ -f "$SENTINEL_HOME/.env.example" ]; then
        info "Creating initial .env configuration file from template..."
        cp "$SENTINEL_HOME/.env.example" "$SENTINEL_HOME/.env"
        chmod 600 "$SENTINEL_HOME/.env"
        success "Created $SENTINEL_HOME/.env (mode 600)"
    fi
}

# ── Binary Launcher Creation ──────────────────────────────────────────────────
setup_launcher_binary() {
    info "Configuring SentinelAPI launcher binaries..."
    mkdir -p "$SENTINEL_HOME/bin"
    mkdir -p "$LOCAL_BIN"

    SENTINEL_BIN="$SENTINEL_HOME/bin/sentinel"

    cat << 'EOF' > "$SENTINEL_BIN"
#!/usr/bin/env bash
# ==============================================================================
# SentinelAPI CLI Executable Launcher
# ==============================================================================
set -e

# Resolve script directory following symlinks
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
  DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
RESOLVED_BIN_DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"
INSTALL_ROOT="$( cd -P "$RESOLVED_BIN_DIR/.." >/dev/null 2>&1 && pwd )"

# Default to resolved installation directory if it has the package
if [ -f "$INSTALL_ROOT/sentinelapi/main.py" ]; then
    SENTINEL_HOME="$INSTALL_ROOT"
else
    SENTINEL_HOME="${SENTINEL_HOME:-$HOME/.sentinel}"
fi

export SENTINEL_HOME
export PYTHONPATH="$SENTINEL_HOME:${PYTHONPATH:-}"

if [ ! -f "$SENTINEL_HOME/.venv/bin/python" ]; then
    echo "Error: SentinelAPI virtual environment not found in $SENTINEL_HOME." >&2
    echo "Please re-run installer: curl -fsSL https://raw.githubusercontent.com/iblameyuvraj/SentinelAPI/main/install.sh | bash" >&2
    exit 1
fi

exec "$SENTINEL_HOME/.venv/bin/python" -m sentinelapi.main "$@"
EOF

    chmod +x "$SENTINEL_BIN"
    ln -sf "$SENTINEL_BIN" "$LOCAL_BIN/sentinel"

    success "Created executable launcher: $SENTINEL_BIN"
    success "Symlinked to user binary path: $LOCAL_BIN/sentinel"
}

# ── Shell Integration (Zsh & Bash) ────────────────────────────────────────────
configure_shell() {
    info "Configuring shell environment and auto-completion..."

    # Normalize home path representation for clean export
    HOME_NORMALIZED="${SENTINEL_HOME/#$HOME/\$HOME}"

    SHELL_CONFIG_BLOCK=$(cat << EOF
# >>> SentinelAPI Security Engine >>>
export SENTINEL_HOME="$HOME_NORMALIZED"
export PATH="\$SENTINEL_HOME/bin:\$HOME/.local/bin:\$PATH"

# SentinelAPI Zsh Autocompletion
if [[ -n "\$ZSH_VERSION" ]]; then
    _sentinel_completion() {
        local -a options
        options=(
            "--spec:Path or URL to OpenAPI / Swagger specification file"
            "--base-url:Target API base URL (e.g. https://api.target.com)"
            "--token:Bearer token for authenticated endpoint testing"
            "--cookie:Cookie string for authenticated endpoint testing"
            "--burst:Burst request count for rate limiting tests (default: 20)"
            "--no-ai:Skip AI report generation"
            "--ci:CI mode: Fail-closed non-zero exit code"
            "--email:Send automated email report via Brevo"
            "--no-email:Disable automated email report dispatch"
            "-h:Show help menu"
            "--help:Show help menu"
        )
        _describe "sentinel" options
    }
    compdef _sentinel_completion sentinel 2>/dev/null || true
fi
# <<< SentinelAPI Security Engine <<<
EOF
)

    # Target configuration files
    TARGET_FILES=()

    # Always configure ~/.zshrc if user uses zsh or file exists
    ZSHRC="$HOME/.zshrc"
    if [ -f "$ZSHRC" ] || [ "${SHELL##*/}" = "zsh" ] || [ -n "${ZSH_VERSION:-}" ]; then
        touch "$ZSHRC"
        TARGET_FILES+=("$ZSHRC")
    fi

    # Also configure ~/.bashrc if it exists
    BASHRC="$HOME/.bashrc"
    if [ -f "$BASHRC" ]; then
        TARGET_FILES+=("$BASHRC")
    fi

    # macOS login shells sometimes read ~/.zprofile
    if [ "$(uname -s)" = "Darwin" ]; then
        ZPROFILE="$HOME/.zprofile"
        if [ -f "$ZPROFILE" ]; then
            TARGET_FILES+=("$ZPROFILE")
        fi
    fi

    # De-duplicate target files
    UPDATED_FILES=()
    for rc in "${TARGET_FILES[@]}"; do
        ALREADY_DONE=false
        for done_file in "${UPDATED_FILES[@]:-}"; do
            if [ "$done_file" = "$rc" ]; then
                ALREADY_DONE=true
                break
            fi
        done
        [ "$ALREADY_DONE" = true ] && continue

        if grep -q "SentinelAPI Security Engine" "$rc" 2>/dev/null; then
            # Replace existing block cleanly
            awk '
                /# >>> SentinelAPI Security Engine >>>/ { skip=1; next }
                /# <<< SentinelAPI Security Engine <<</ { skip=0; next }
                !skip { print }
            ' "$rc" > "$rc.tmp"
            printf "\n%s\n" "$SHELL_CONFIG_BLOCK" >> "$rc.tmp"
            mv "$rc.tmp" "$rc"
            success "Updated SentinelAPI configuration in $rc"
        else
            printf "\n%s\n" "$SHELL_CONFIG_BLOCK" >> "$rc"
            success "Configured SentinelAPI in $rc"
        fi
        UPDATED_FILES+=("$rc")
    done
}

# ── Self-Verification ─────────────────────────────────────────────────────────
verify_installation() {
    info "Verifying SentinelAPI installation and engine readiness..."
    if "$SENTINEL_HOME/bin/sentinel" --help >/dev/null 2>&1; then
        success "Engine verification passed: 'sentinel' is operational!"
    else
        warn "Could not run automated self-test via launcher. Please inspect $SENTINEL_HOME."
    fi
}

# ── Final Instructions ────────────────────────────────────────────────────────
print_finish_message() {
    printf "\n"
    printf "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"
    printf "${GREEN}${BOLD}  ✨ SentinelAPI Installation & Zsh Setup Complete! ✨${RESET}\n"
    printf "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n\n"

    printf "${BOLD}Installation Directory:${RESET}  %s\n" "$SENTINEL_HOME"
    printf "${BOLD}Executable Binary:${RESET}       %s\n" "$SENTINEL_HOME/bin/sentinel"
    printf "${BOLD}PATH Symlink:${RESET}            %s/sentinel\n" "$LOCAL_BIN"
    printf "${BOLD}Configuration File:${RESET}      %s/.env\n" "$SENTINEL_HOME"
    printf "\n"

    printf "${CYAN}${BOLD}⚡ Quickstart Next Steps:${RESET}\n"
    printf "  ${BOLD}1. Reload your current Zsh shell:${RESET}\n"
    printf "     ${YELLOW}source ~/.zshrc${RESET}  ${DIM}(or open a new terminal window)${RESET}\n\n"

    printf "  ${BOLD}2. Launch interactive Cyberpunk Terminal UI:${RESET}\n"
    printf "     ${GREEN}sentinel${RESET}\n\n"

    printf "  ${BOLD}3. Or run automated audit against an API spec:${RESET}\n"
    printf "     ${CYAN}sentinel --spec api_spec.json --base-url https://api.example.com${RESET}\n\n"

    printf "  ${BOLD}4. Configure AI Engine & Email Keys (optional):${RESET}\n"
    printf "     ${DIM}Edit %s/.env to configure Gemini, OpenAI, Claude, or Brevo.${RESET}\n\n" "$SENTINEL_HOME"

    if [ "$IS_LOCAL_REPO" = true ]; then
        printf "${DIM}To unlink binary: rm -f %s/sentinel %s/bin/sentinel${RESET}\n\n" "$LOCAL_BIN" "$SENTINEL_HOME"
    else
        printf "${DIM}To uninstall at any time: rm -rf %s %s/sentinel${RESET}\n\n" "$SENTINEL_HOME" "$LOCAL_BIN"
    fi
}

# ── Main Entrypoint ───────────────────────────────────────────────────────────
main() {
    print_banner
    check_dependencies
    setup_source_files
    setup_virtualenv
    setup_launcher_binary
    configure_shell
    verify_installation
    print_finish_message
}

main "$@"
