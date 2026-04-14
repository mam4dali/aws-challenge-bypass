#!/usr/bin/env bash
set -e

# cd to project root (parent of this script's folder)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "============================================"
echo "  Installing AWS Challenge Bypass"
echo "============================================"
echo

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 is not installed."
    echo "        Install via: brew install python3 (macOS) or apt install python3 python3-venv (Linux)"
    exit 1
fi

echo "[1/3] Creating virtual environment..."
if [ -d "venv" ]; then
    echo "      venv already exists, skipping."
else
    python3 -m venv venv
fi

echo "[2/3] Installing dependencies..."
source venv/bin/activate
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt

echo "[3/3] Setting up .env file..."
if [ -f ".env" ]; then
    echo "      .env already exists, skipping."
else
    cp .env.example .env
    echo "      .env created from .env.example"
    echo "      Edit .env to customize your settings."
fi

echo
echo "============================================"
echo "  Installation complete!"
echo "  Run the project with: ./run/run.sh"
echo "============================================"
