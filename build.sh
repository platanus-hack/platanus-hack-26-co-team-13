#!/bin/bash
# Build script for Render - ensure Python backend runs
set -e

echo "🔨 Building Platanus Telegram Supervisor Bot Backend..."
echo "📦 Installing Python dependencies..."

cd backend
pip install -r requirements.txt

echo "✅ Build complete - backend ready to start"
