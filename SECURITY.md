# Security Policy

## Supported Versions

Only the latest release of KernelWatch is currently supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Reporting a Vulnerability

**Do NOT report security vulnerabilities via public GitHub issues.**

If you have discovered a security vulnerability in KernelWatch (e.g., local privilege escalation via the CLI, unsafe file handling, RCE in the UI), please report it privately.

### Reporting Process

1.  Contact the maintainers via email at `coderdayton14@gmail.com` or discord (xxbbl).
2.  Include details about the vulnerability, steps to reproduce, and potential impact.
3.  We will acknowledge receipt within 48 hours.
4.  We will provide a timeline for the fix and coordinate the release.

## Vulnerable Drivers

This tool is designed to **find** vulnerable drivers. Finding a vulnerable driver using this tool is **not** a vulnerability in the tool itself.

*   If you find a new vulnerable driver, please report it to [LOLDrivers](https://github.com/magicsword-io/LOLDrivers).
*   If you find a bug in our analysis engine (e.g., false negative), please open a GitHub Issue.
