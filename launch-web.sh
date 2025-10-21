#!/bin/bash

# GitHub Malware Scanner - Web Dashboard Launcher
# This script sets up and launches the web frontend for exploring TimescaleDB data

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_DIR="$SCRIPT_DIR/web"

echo "=========================================="
echo "GitHub Malware Scanner - Web Dashboard"
echo "=========================================="
echo ""

# Check if .env exists
if [ ! -f "$SCRIPT_DIR/.env" ]; then
    echo "ERROR: .env file not found in $SCRIPT_DIR"
    echo "Please ensure your database credentials are configured in .env"
    exit 1
fi

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    echo "Please install Python 3 to continue"
    exit 1
fi

# Check if we're in a virtual environment, if not create one
if [ -z "$VIRTUAL_ENV" ]; then
    echo "Setting up Python virtual environment..."

    if [ ! -d "$WEB_DIR/venv" ]; then
        echo "Creating virtual environment..."
        python3 -m venv "$WEB_DIR/venv"
    fi

    echo "Activating virtual environment..."
    source "$WEB_DIR/venv/bin/activate"
else
    echo "Virtual environment already active: $VIRTUAL_ENV"
fi

# Install dependencies
echo ""
echo "Installing Python dependencies..."
pip install -q --upgrade pip
pip install -q -r "$WEB_DIR/requirements.txt"

# Copy .env to web directory if it doesn't exist there
if [ ! -f "$WEB_DIR/.env" ]; then
    echo "Copying .env to web directory..."
    cp "$SCRIPT_DIR/.env" "$WEB_DIR/.env"
fi

# Launch the application
echo ""
echo "=========================================="
echo "Starting web server..."
echo "=========================================="
echo ""
echo "Dashboard will be available at:"
echo "  http://localhost:5000"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

cd "$WEB_DIR"
python3 app.py
