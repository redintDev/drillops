#!/usr/bin/env bash
# ==============================================================================
# SafeMigrate Turnkey 1-Command Installer
# Zero-Downtime Database Migration Linter & Safety Auditor
# Supports Linux, macOS, and WSL with PEP 668 externally managed Python environments.
# ==============================================================================

set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

# Flag handling with safe unbound variable default
ARG1="${1:-}"
if [ "$ARG1" = "--help" ] || [ "$ARG1" = "-h" ]; then
    echo "Usage: install.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --help, -h          Show this help message and exit"
    echo "  --version           Print SafeMigrate installer version"
    echo "  --check <dir>       Run 'safemigrate check <dir>' immediately after install"
    exit 0
fi

if [ "$ARG1" = "--version" ]; then
    echo "SafeMigrate Installer v0.1.0"
    exit 0
fi

echo -e "${CYAN}${BOLD}"
echo "  ____        __      __  __ _                 _       "
echo " / ___|  __ _|  ____ |  \/  (_) __ _ _ __ __ _| |_ ___ "
echo " \___ \ / _\` | |_ / _ \ |\/| | |/ _\` | '__/ _\` | __/ _ \ "
echo "  ___) | (_| |  _|  __/ |  | | | (_| | | | (_| | ||  __/ "
echo " |____/ \__,_|_|  \___|_|  |_|_|\__, |_|  \__,_|\__\___| "
echo "                                |___/                  "
echo -e "${RESET}"
echo -e "${BOLD}SafeMigrate: Zero-Downtime Database Migration Linter & Safety Auditor${RESET}\n"

# 1. Detect Python 3.9+
PYTHON_BIN=""
for cmd in python3 python; do
    if command -v "$cmd" >/dev/null 2>&1; then
        PY_MAJOR=$("$cmd" -c 'import sys; print(sys.version_info.major)' 2>/dev/null || echo "0")
        PY_MINOR=$("$cmd" -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || echo "0")
        if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 9 ]; then
            PYTHON_BIN="$cmd"
            PY_VER="$PY_MAJOR.$PY_MINOR"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}[ERROR] Python 3.9 or higher is required.${RESET}"
    echo "Please install Python 3.9+ and re-run this script."
    exit 1
fi

echo -e "${GREEN}[✔] Detected Python ${PY_VER} (${PYTHON_BIN})${RESET}"

# 2. Determine Installation Source & Target Environment
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
LOCAL_SOURCE=""
if [ -f "$INSTALL_DIR/pyproject.toml" ]; then
    LOCAL_SOURCE="$INSTALL_DIR"
elif [ -d "$INSTALL_DIR/projects/safemigrate" ] && [ -f "$INSTALL_DIR/projects/safemigrate/pyproject.toml" ]; then
    LOCAL_SOURCE="$INSTALL_DIR/projects/safemigrate"
fi

# If already inside an active virtualenv, install directly into it
if [ -n "$VIRTUAL_ENV" ]; then
    echo -e "${CYAN}[i] Installing inside active virtualenv (${VIRTUAL_ENV})...${RESET}"
    if [ -n "$LOCAL_SOURCE" ]; then
        "$VIRTUAL_ENV/bin/pip" install -q -e "$LOCAL_SOURCE"
    else
        "$VIRTUAL_ENV/bin/pip" install -q "git+https://github.com/redintDev/drillops.git#subdirectory=safemigrate"
    fi
    SAFEMIGRATE_CMD="$VIRTUAL_ENV/bin/safemigrate"
elif [ -d "$INSTALL_DIR/.venv" ] && [ -f "$INSTALL_DIR/.venv/bin/pip" ]; then
    echo -e "${CYAN}[i] Installing into workspace virtualenv ($INSTALL_DIR/.venv)...${RESET}"
    if [ -n "$LOCAL_SOURCE" ]; then
        "$INSTALL_DIR/.venv/bin/pip" install -q -e "$LOCAL_SOURCE"
    else
        "$INSTALL_DIR/.venv/bin/pip" install -q "git+https://github.com/redintDev/drillops.git#subdirectory=safemigrate"
    fi
    SAFEMIGRATE_CMD="$INSTALL_DIR/.venv/bin/safemigrate"
else
    # Isolated user installation to ~/.safemigrate/venv (PEP 668 compliant)
    USER_VENV="$HOME/.safemigrate/venv"
    echo -e "${CYAN}[i] Creating isolated environment at ${USER_VENV}...${RESET}"
    mkdir -p "$HOME/.safemigrate"
    if [ ! -d "$USER_VENV" ]; then
        "$PYTHON_BIN" -m venv "$USER_VENV"
    fi
    "$USER_VENV/bin/pip" install -q --upgrade pip setuptools
    if [ -n "$LOCAL_SOURCE" ]; then
        "$USER_VENV/bin/pip" install -q -e "$LOCAL_SOURCE"
    else
        "$USER_VENV/bin/pip" install -q "git+https://github.com/redintDev/drillops.git#subdirectory=safemigrate"
    fi

    # Symlink to ~/.local/bin
    mkdir -p "$HOME/.local/bin"
    ln -sf "$USER_VENV/bin/safemigrate" "$HOME/.local/bin/safemigrate"
    SAFEMIGRATE_CMD="$HOME/.local/bin/safemigrate"

    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        export PATH="$HOME/.local/bin:$PATH"
        echo -e "${YELLOW}[!] Tip: Add ~/.local/bin to your PATH in ~/.bashrc or ~/.zshrc:${RESET}"
        echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
fi

echo -e "\n${GREEN}${BOLD}[✔] SafeMigrate successfully installed!${RESET}"
echo -e "${CYAN}------------------------------------------------------------${RESET}"
echo -e "Quickstart Guide:"
echo -e "  1. Lint a migration script:        ${BOLD}${SAFEMIGRATE_CMD} lint ./migrations/001_users.sql${RESET}"
echo -e "  2. Audit directory recursively:    ${BOLD}${SAFEMIGRATE_CMD} check ./migrations/${RESET}"
echo -e "  3. Output machine-readable JSON:   ${BOLD}${SAFEMIGRATE_CMD} check ./migrations/ --format json${RESET}"
echo -e "  4. Use in GitHub Actions:          ${BOLD}uses: redintDev/drillops/safemigrate@main${RESET}"
echo -e "  5. Try live browser simulator:     ${BOLD}https://redintdev.github.io/drillops/safemigrate/${RESET}"
echo -e "${CYAN}------------------------------------------------------------${RESET}\n"

ARG2="${2:-}"
if [ "$ARG1" = "--check" ] && [ -n "$ARG2" ]; then
    echo -e "${YELLOW}[i] Running migration check on $ARG2...${RESET}\n"
    "$SAFEMIGRATE_CMD" check "$ARG2"
fi
