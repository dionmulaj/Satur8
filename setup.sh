#!/bin/bash

# Satur8 Setup Script
# This script helps set up the environment for Satur8

echo "╔═══════════════════════════════════════╗"
echo "║      Satur8 Installation Script       ║"
echo "╚═══════════════════════════════════════╝"
echo ""

if [ -d "venv" ]; then
    echo "[INFO] Virtual environment already exists"
    read -p "Do you want to recreate it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "[INFO] Removing existing virtual environment..."
        rm -rf venv
    else
        echo "[INFO] Using existing virtual environment..."
    fi
fi

if [ ! -d "venv" ]; then
    echo "[INFO] Creating virtual environment..."
    python3 -m venv venv
    
    if [ $? -eq 0 ]; then
        echo "[OK] Virtual environment created"
    else
        echo "[ERROR] Failed to create virtual environment"
        exit 1
    fi
fi

echo "[INFO] Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "[OK] Dependencies installed successfully"
else
    echo "[ERROR] Failed to install dependencies"
    deactivate
    exit 1
fi

deactivate

echo ""
echo "[INFO] Setting up configuration..."

if [ ! -f .env ]; then
    cp .env.example .env
    echo "[OK] Created .env file (please edit it to set your interface)"
else
    echo "[INFO] .env file already exists"
fi

echo ""
echo "[INFO] Available network interfaces:"
echo "--------------------------------"
ifconfig | grep -E "^[a-z]" | cut -d: -f1 | sed 's/^/  - /'

echo ""
echo "[OK] Setup complete!"
echo ""
echo "[INFO] Next steps:"
echo "   1. Edit .env file and set your wireless interface"
echo "   2. Monitor mode is handled automatically on macOS -- no manual step needed"
echo "   3. Run: ./start.sh (or sudo ./start.sh if root access is needed)"
echo ""
echo "[INFO] The virtual environment will be activated automatically when using start.sh"
echo "[WARN] Remember: Use only on networks you own or have permission to test"
echo ""
