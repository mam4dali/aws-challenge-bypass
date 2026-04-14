#!/usr/bin/env bash
set -e

# cd to project root (parent of this script's folder)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Check venv exists
if [ ! -d "venv" ]; then
    echo "[ERROR] Virtual environment not found."
    echo "        Run ./install/install.sh first."
    exit 1
fi

# Check .env exists
if [ ! -f ".env" ]; then
    echo "[ERROR] .env file not found."
    echo "        Run ./install/install.sh first."
    exit 1
fi

source venv/bin/activate
echo "Starting server..."
python run.py
