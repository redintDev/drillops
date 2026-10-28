#!/usr/bin/env bash
# ==============================================================================
# DrillOps Turnkey 1-Command Installer
# Supports Linux, macOS, WSL with PEP 668 externally managed Python environments.
# ==============================================================================

set -e

BOLD="\033[1m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

echo -e "${CYAN}${BOLD}"
echo "  ____       _ _ _  ___             "
echo " |  _ \ _ __(_) | |/ _ \ _ __  ___  "
echo " | | | | '__| | | | | | | '_ \/ __| "
echo " | |_| | |  | | | | |_| | |_) \__ \ "
echo " |____/|_|  |_|_|_|\___/| .__/|___/ "
echo "                        |_|         "
echo -e "${RESET}"
echo -e "${BOLD}DrillOps: Automated Database Disaster Recovery Verification & SOC2 Certifier${RESET}\n"

# 1. Detect Python 3.10+
PYTHON_BIN=""
for cmd in python3 python; do
    if command -v "$cmd" >/dev/null 2>&1; then
        PY_MAJOR=$("$cmd" -c 'import sys; print(sys.version_info.major)' 2>/dev/null || echo "0")
        PY_MINOR=$("$cmd" -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || echo "0")
        if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 10 ]; then
            PYTHON_BIN="$cmd"
            PY_VER="$PY_MAJOR.$PY_MINOR"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}[ERROR] Python 3.10 or higher is required.${RESET}"
    echo "Please install Python 3.10+ and re-run this script."
    exit 1
fi

echo -e "${GREEN}[✔] Detected Python ${PY_VER} (${PYTHON_BIN})${RESET}"

# 2. Determine Installation Target Environment
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
LOCAL_SOURCE=""
if [ -f "$INSTALL_DIR/pyproject.toml" ]; then
    LOCAL_SOURCE="$INSTALL_DIR"
elif [ -d "$INSTALL_DIR/projects/drillops" ] && [ -f "$INSTALL_DIR/projects/drillops/pyproject.toml" ]; then
    LOCAL_SOURCE="$INSTALL_DIR/projects/drillops"
fi

# If already inside an active virtualenv, install directly into it
if [ -n "$VIRTUAL_ENV" ]; then
    echo -e "${CYAN}[i] Installing inside active virtualenv (${VIRTUAL_ENV})...${RESET}"
    if [ -n "$LOCAL_SOURCE" ]; then
        "$VIRTUAL_ENV/bin/pip" install -q -e "$LOCAL_SOURCE"
    else
        "$VIRTUAL_ENV/bin/pip" install -q "git+https://github.com/redintDev/drillops.git"
    fi
    DRILLOPS_CMD="$VIRTUAL_ENV/bin/drillops"
elif [ -d "$INSTALL_DIR/.venv" ] && [ -f "$INSTALL_DIR/.venv/bin/pip" ]; then
    echo -e "${CYAN}[i] Installing into repository virtualenv ($INSTALL_DIR/.venv)...${RESET}"
    if [ -n "$LOCAL_SOURCE" ]; then
        "$INSTALL_DIR/.venv/bin/pip" install -q -e "$LOCAL_SOURCE"
    else
        "$INSTALL_DIR/.venv/bin/pip" install -q "git+https://github.com/redintDev/drillops.git"
    fi
    DRILLOPS_CMD="$INSTALL_DIR/.venv/bin/drillops"
else
    # Isolated user installation to ~/.drillops/venv (PEP 668 compliant)
    USER_VENV="$HOME/.drillops/venv"
    echo -e "${CYAN}[i] Creating isolated environment at ${USER_VENV}...${RESET}"
    mkdir -p "$HOME/.drillops"
    if [ ! -d "$USER_VENV" ]; then
        "$PYTHON_BIN" -m venv "$USER_VENV"
    fi
    "$USER_VENV/bin/pip" install -q --upgrade pip setuptools
    if [ -n "$LOCAL_SOURCE" ]; then
        "$USER_VENV/bin/pip" install -q -e "$LOCAL_SOURCE"
    else
        "$USER_VENV/bin/pip" install -q "git+https://github.com/redintDev/drillops.git"
    fi

    # Symlink to ~/.local/bin
    mkdir -p "$HOME/.local/bin"
    ln -sf "$USER_VENV/bin/drillops" "$HOME/.local/bin/drillops"
    DRILLOPS_CMD="$HOME/.local/bin/drillops"

    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        export PATH="$HOME/.local/bin:$PATH"
        echo -e "${YELLOW}[!] Tip: Add ~/.local/bin to your PATH in ~/.bashrc or ~/.zshrc:${RESET}"
        echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
fi

echo -e "\n${GREEN}${BOLD}[✔] DrillOps successfully installed!${RESET}"
echo -e "${CYAN}------------------------------------------------------------${RESET}"
echo -e "Quickstart Guide:"
echo -e "  1. Run interactive sandbox drill:  ${BOLD}${DRILLOPS_CMD} demo${RESET}"
echo -e "  2. View compliance dashboard:     ${BOLD}${DRILLOPS_CMD} serve --port 8787${RESET}"
echo -e "  3. Start automated watcher:        ${BOLD}${DRILLOPS_CMD} watch --engine sqlite${RESET}"
echo -e "  4. Generate SOC2 auditor pack:    ${BOLD}${DRILLOPS_CMD} audit-pack --out ./dossier${RESET}"
echo -e "${CYAN}------------------------------------------------------------${RESET}\n"

if [ "$1" == "--demo" ]; then
    echo -e "${YELLOW}[i] Running instant onboarding demo...${RESET}\n"
    $DRILLOPS_CMD demo
fi
