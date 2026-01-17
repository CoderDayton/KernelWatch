# Driver Search

<img src="assets/logo.svg" width="180" align="right" alt="Driver Search Logo" />

Vulnerable driver research tooling for blocklist contribution (Microsoft HVCI, LOLDrivers).

## Purpose

Proactively hunt for vulnerable Windows kernel drivers that could be abused for privilege escalation (BYOVD attacks) and contribute them to blocklists before they're exploited in the wild.

## Features

- **Multi-source monitoring**: NVD/CVE feeds, LOLDrivers GitHub, VirusTotal, vendor sites
- **Automated analysis**: PE parsing, import analysis, IOCTL detection, dangerous pattern matching
- **Risk scoring**: Prioritize drivers based on vulnerability indicators
- **Export formats**: LOLDrivers YAML, MSRC reports, YARA rules
- **Tauri UI**: Modern semantic interface with dark mode and dashboard

## Prerequisites

- **Python**: 3.10+
- **Node.js**: 20+
- **Rust**: 1.77+
- **Build Tools**:
  - **Linux**: `sudo apt-get install -y libgtk-3-dev libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf`
  - **Windows**: C++ Build Tools (via Visual Studio Installer)
  - **macOS**: Xcode Command Line Tools

## Installation

```bash
# Clone and install
git clone https://github.com/yourusername/driver-search.git
cd driver-search

# Install Python dependencies
uv sync
```

## Build

This project uses a hybrid build system (Python Sidecar + Rust/Tauri Frontend).

### Quick Build (All-in-one)

```bash
./build.sh
```

### Manual Build Steps

1. **Build Python Sidecar**
   ```bash
   ./scripts/build-sidecar.sh
   ```
   *This creates the standalone executable in `ui/src-tauri/binaries/`.*

2. **Build Tauri App**
   ```bash
   cd ui
   npm install
   npm run tauri:build
   ```

## Development

```bash
# Start backend in watch mode (if applicable) or run CLI directly
uv run driver-search --help

# Start UI in dev mode
cd ui
npm run tauri:dev
```

## Configuration

Create a `.env` file with your API keys:

```env
DRIVER_SEARCH_NVD_API_KEY=your-nvd-api-key
DRIVER_SEARCH_VIRUSTOTAL_API_KEY=your-vt-api-key
DRIVER_SEARCH_GITHUB_TOKEN=your-github-token
```

## Contributing to Blocklists

### LOLDrivers

1. Find a vulnerable driver
2. Analyze with `driver-search analyze`
3. Export with `driver-search export loldrivers`
4. Submit PR to [magicsword-io/LOLDrivers](https://github.com/magicsword-io/LOLDrivers)

## License

MIT
