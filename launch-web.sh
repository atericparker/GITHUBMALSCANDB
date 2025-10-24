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

# Ensure .env in the web directory stays symlinked to the project root
ROOT_ENV="$SCRIPT_DIR/.env"
WEB_ENV="$WEB_DIR/.env"

if [ -L "$WEB_ENV" ]; then
    if [ "$(readlink "$WEB_ENV")" != "$ROOT_ENV" ]; then
        echo "Updating .env symlink in web directory..."
        ln -sf "$ROOT_ENV" "$WEB_ENV"
    fi
elif [ -e "$WEB_ENV" ]; then
    echo "Replacing existing .env in web directory with symlink..."
    rm "$WEB_ENV"
    ln -s "$ROOT_ENV" "$WEB_ENV"
else
    echo "Creating .env symlink in web directory..."
    ln -s "$ROOT_ENV" "$WEB_ENV"
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
