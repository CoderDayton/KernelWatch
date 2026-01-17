<div align="center">
  <img src="assets/logo.svg" width="160" alt="Driver Search Logo" />
  <h1>Driver Search</h1>
  <p><strong>Proactive Vulnerable Driver Hunting</strong></p>

  <p>
    <a href="https://github.com/yourusername/driver-search/actions/workflows/ci.yml">
      <img src="https://img.shields.io/github/actions/workflow/status/yourusername/driver-search/ci.yml?branch=main&label=build&style=flat-square" alt="Build Status" />
    </a>
    <a href="https://github.com/yourusername/driver-search/blob/main/LICENSE">
      <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License" />
    </a>
    <img src="https://img.shields.io/badge/python-3.10+-yellow?style=flat-square&logo=python" alt="Python Version" />
    <img src="https://img.shields.io/badge/rust-1.77+-orange?style=flat-square&logo=rust" alt="Rust Version" />
    <img src="https://img.shields.io/badge/style-ruff-000000?style=flat-square" alt="Code Style" />
  </p>
  
  <p><em>A specialized toolkit for security researchers to identify vulnerable Windows kernel drivers<br/>before they are exploited in the wild.</em></p>
</div>

<br/>

## Overview

**Driver Search** bridges the gap between driver discovery and defensive blocklisting. It automates the tedious process of hunting for "Bring Your Own Vulnerable Driver" (BYOVD) candidates—signed drivers that expose dangerous primitives like MSR access or physical memory mapping.

By combining multi-source monitoring with automated static analysis, it helps researchers identify high-risk drivers and contribute them to [LOLDrivers](https://github.com/magicsword-io/LOLDrivers) or the Microsoft HVCI blocklist.

## Features

- **🛡️ Automated Analysis**: Static analysis of PE files to detect dangerous imports (`MmMapIoSpace`, `__readmsr`), IOCTL handlers, and potentially unsafe opcodes via Capstone disassembly.
- **📡 Multi-Source Intelligence**: Monitors NVD for new CVEs, tracks LOLDrivers updates, and integrates with VirusTotal to find low-detection candidates.
- **📊 Risk Scoring**: Assigns confidence scores to drivers based on capability exposure, signature status, and blocklist absence.
- **🖥️ Modern Interface**: A semantic, dark-themed dashboard built with Tauri and SolidJS for managing your research workflow.
- **📝 Standardized Output**: Generates ready-to-submit YAML for LOLDrivers and YARA rules for detection.

## Prerequisites

- **Python**: 3.10+
- **Node.js**: 20+
- **Rust**: 1.77+
- **Build Tools**:
  - **Linux**: `sudo apt-get install -y libgtk-3-dev libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf`
  - **Windows**: C++ Build Tools (via Visual Studio Installer)
  - **macOS**: Xcode Command Line Tools

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/driver-search.git
cd driver-search

# Install Python dependencies
uv sync
```

### Building the App

This project uses a hybrid architecture (Python backend + Tauri frontend). We provide a unified build script:

```bash
./build.sh
```

*This will compile the Python sidecar, build the frontend, and generate the final application executable.*

## Usage

### CLI (Headless)

Perfect for CI pipelines or server-side monitoring.

```bash
# Analyze a specific driver
uv run driver-search analyze /path/to/suspicious.sys

# Monitor sources for new threats (continuous mode)
uv run driver-search monitor --sources nvd,loldrivers

# Export findings for LOLDrivers contribution
uv run driver-search export loldrivers --hash <SHA256>
```

### Graphical Interface

Launch the desktop app to view the dashboard, visualize risk scores, and manage your driver database.

```bash
cd ui
npm run tauri:dev
```

## Configuration

Create a `.env` file in the root directory to enable external API integrations:

```env
DRIVER_SEARCH_NVD_API_KEY=your-key-here        # For higher rate limits
DRIVER_SEARCH_VIRUSTOTAL_API_KEY=your-key-here # For detection ratios
DRIVER_SEARCH_GITHUB_TOKEN=your-token-here     # For LOLDrivers sync
```

## Contributing

We welcome contributions to improve detection heuristics or add new data sources.

1. **Found a vulnerable driver?** Please report it to [LOLDrivers](https://github.com/magicsword-io/LOLDrivers) first.
2. **Improving the tool?** Open a PR with your changes. Please ensure `lefthook` checks pass.

## License

MIT © 2026
