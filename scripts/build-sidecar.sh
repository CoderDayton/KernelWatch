#!/bin/bash
# Build script for Python sidecar binary
# This creates a standalone executable using PyInstaller

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
UI_DIR="$PROJECT_ROOT/ui"
BINARIES_DIR="$UI_DIR/src-tauri/binaries"

echo "Building driver-search sidecar binary..."

# Ensure binaries directory exists
mkdir -p "$BINARIES_DIR"

# Detect target triple
case "$(uname -s)" in
    Linux*)
        case "$(uname -m)" in
            x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
            aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
            *) TARGET="unknown-linux" ;;
        esac
        ;;
    Darwin*)
        case "$(uname -m)" in
            x86_64) TARGET="x86_64-apple-darwin" ;;
            arm64) TARGET="aarch64-apple-darwin" ;;
            *) TARGET="unknown-darwin" ;;
        esac
        ;;
    MINGW*|MSYS*|CYGWIN*)
        TARGET="x86_64-pc-windows-msvc"
        ;;
    *)
        echo "Unknown platform"
        exit 1
        ;;
esac

echo "Target: $TARGET"

# Build with PyInstaller
cd "$PROJECT_ROOT"

# Install pyinstaller if needed
uv pip install pyinstaller

# Create the executable
uv run pyinstaller \
    --name "driver-search-$TARGET" \
    --onefile \
    --console \
    --clean \
    --distpath "$BINARIES_DIR" \
    --specpath "$PROJECT_ROOT/build" \
    --workpath "$PROJECT_ROOT/build/pyinstaller" \
    src/driver_search/cli.py

echo "Built: $BINARIES_DIR/driver-search-$TARGET"
echo "Done!"
