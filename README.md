# Driver Search

Vulnerable driver research tooling for blocklist contribution (Microsoft HVCI, LOLDrivers).

## Purpose

Proactively hunt for vulnerable Windows kernel drivers that could be abused for privilege escalation (BYOVD attacks) and contribute them to blocklists before they're exploited in the wild.

## Features

- **Multi-source monitoring**: NVD/CVE feeds, LOLDrivers GitHub, VirusTotal, vendor sites
- **Automated analysis**: PE parsing, import analysis, IOCTL detection, dangerous pattern matching
- **Risk scoring**: Prioritize drivers based on vulnerability indicators
- **Export formats**: LOLDrivers YAML, MSRC reports

## Installation

```bash
# Clone and install
git clone https://github.com/yourusername/driver-search.git
cd driver-search
uv sync  # or pip install -e ".[dev]"
```

## Configuration

Create a `.env` file with your API keys:

```env
DRIVER_SEARCH_NVD_API_KEY=your-nvd-api-key
DRIVER_SEARCH_VIRUSTOTAL_API_KEY=your-vt-api-key
DRIVER_SEARCH_GITHUB_TOKEN=your-github-token
```

## Usage

```bash
# Analyze a driver
driver-search analyze /path/to/driver.sys

# Search NVD for driver-related CVEs
driver-search search-nvd "motherboard overclock" --since 2025-01-01

# Monitor sources for new drivers
driver-search monitor --sources nvd,loldrivers

# Sync LOLDrivers database
driver-search sync-loldrivers

# Export analysis as LOLDrivers YAML
driver-search export loldrivers --hash abc123...

# Show dashboard
driver-search dashboard
```

## Contributing to Blocklists

### LOLDrivers

1. Find a vulnerable driver
2. Analyze with `driver-search analyze`
3. Export with `driver-search export loldrivers`
4. Submit PR to [magicsword-io/LOLDrivers](https://github.com/magicsword-io/LOLDrivers)

### Microsoft HVCI Blocklist

1. Document the vulnerability with evidence
2. Submit via [MSRC](https://msrc.microsoft.com/report)
3. Email `secure@microsoft.com` for driver-specific issues

## License

MIT
