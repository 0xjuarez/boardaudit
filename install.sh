#!/bin/sh
# install.sh - boardaudit universal installer (Linux / macOS)
# Usage:
#   ./install.sh [--system] [--dry-run] [--help]
# Default install is per-user: a venv in ~/.local/share/boardaudit/venv
# and a symlink in ~/.local/bin/boardaudit. No sudo is used unless
# --system is passed. The installer is idempotent.

set -eu

SYSTEM=0
DRY_RUN=0

for arg in "$@"; do
    case "$arg" in
        --system) SYSTEM=1 ;;
        --dry-run) DRY_RUN=1 ;;
        --help|-h)
            echo "Usage: ./install.sh [--system] [--dry-run] [--help]"
            echo "  --system   install under /usr/local (uses sudo)"
            echo "  --dry-run  print what would be done, without changing anything"
            exit 0
            ;;
        *) echo "error: unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [ "$SYSTEM" -eq 1 ]; then
    PREFIX="/usr/local/share/boardaudit"
    BIN_DIR="/usr/local/bin"
else
    PREFIX="$HOME/.local/share/boardaudit"
    BIN_DIR="$HOME/.local/bin"
fi
VENV_DIR="$PREFIX/venv"
LINK="$BIN_DIR/boardaudit"

fail() { echo "error: $1" >&2; exit 1; }

# Resolve the project directory (the directory containing this script).
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ "$DRY_RUN" -eq 1 ]; then
    echo "dry-run: would create venv in $VENV_DIR"
    echo "dry-run: would install boardaudit from $SCRIPT_DIR"
    echo "dry-run: would link $LINK -> $VENV_DIR/bin/boardaudit"
    echo "dry-run: would run: boardaudit --version"
    exit 0
fi

# Python check: fail clearly when Python is missing or too old.
if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 was not found. Install Python 3.11 or later first, then run ./install.sh again."
fi
PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]; }; then
    fail "Python $PY_VERSION is too old. boardaudit requires Python 3.11 or later."
fi
echo "Python $PY_VERSION found."

# Optional system packages, only with --system.
if [ "$SYSTEM" -eq 1 ]; then
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq
        sudo apt-get install -y python3 python3-venv python3-pip usbutils
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y python3 python3-venv python3-pip usbutils
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm python python-pip usbutils
    elif command -v brew >/dev/null 2>&1; then
        brew install python
    else
        echo "warning: no supported system package manager found; continuing with the Python venv only."
    fi
fi

# Create (or reuse) the venv. Idempotent: an existing venv is reused.
if [ "$SYSTEM" -eq 1 ]; then
    if [ ! -d "$VENV_DIR" ]; then
        sudo mkdir -p "$PREFIX"
        sudo python3 -m venv "$VENV_DIR"
    fi
    sudo "$VENV_DIR/bin/python" -m pip install --upgrade pip
    sudo "$VENV_DIR/bin/python" -m pip install "$SCRIPT_DIR"
else
    mkdir -p "$PREFIX" "$BIN_DIR"
    if [ ! -d "$VENV_DIR" ]; then
        python3 -m venv "$VENV_DIR"
    fi
    "$VENV_DIR/bin/python" -m pip install --upgrade pip
    "$VENV_DIR/bin/python" -m pip install "$SCRIPT_DIR"
fi

# Symlink the entry point.
if [ "$SYSTEM" -eq 1 ]; then
    sudo ln -sf "$VENV_DIR/bin/boardaudit" "$LINK"
else
    ln -sf "$VENV_DIR/bin/boardaudit" "$LINK"
fi

# Verify.
if ! "$LINK" --version >/dev/null 2>&1; then
    # Fall back to the venv binary directly for diagnosis.
    "$VENV_DIR/bin/boardaudit" --version
    fail "installation finished but 'boardaudit --version' did not run. Check $VENV_DIR/bin/boardaudit."
fi

echo "boardaudit installed: $($LINK --version)"
echo "Binary: $LINK"
if [ "$SYSTEM" -eq 0 ]; then
    case ":$PATH:" in
        *":$BIN_DIR:"*) ;;
        *) echo "Note: $BIN_DIR is not in PATH. Add it with: export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
    esac
fi
