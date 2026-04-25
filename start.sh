#!/bin/bash


SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ ! -d "$SCRIPT_DIR/venv" ]; then
    echo "[ERROR] Virtual environment not found!"
    echo "Please run ./setup.sh first"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then 
    echo "[WARN] Satur8 requires root privileges for packet capture"
    echo "Restarting with sudo..."
    sudo -E "$0" "$@"
    exit $?
fi

source "$SCRIPT_DIR/venv/bin/activate"
python3 main.py
deactivate
