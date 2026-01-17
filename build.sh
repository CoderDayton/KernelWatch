#!/bin/bash
set -e

echo "🚀 Starting Driver Search Build Process..."

# 1. Setup Python Environment
echo "🐍 Setting up Python dependencies..."
if command -v uv >/dev/null 2>&1; then
    uv sync
else
    echo "❌ 'uv' not found. Please install uv first."
    exit 1
fi

# 2. Build Python Sidecar
echo "📦 Building Python Sidecar binary..."
chmod +x scripts/build-sidecar.sh
./scripts/build-sidecar.sh

# 3. Setup Frontend Environment
echo "🎨 Setting up UI dependencies..."
cd ui
npm install

# 4. Build Tauri App
echo "🦀 Building Tauri Application..."
npm run tauri:build

echo "✅ Build Complete!"
echo "   Artifacts located in: ui/src-tauri/target/release/bundle/"
