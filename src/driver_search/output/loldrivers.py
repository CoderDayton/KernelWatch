"""LOLDrivers YAML output formatter."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from driver_search.models import AnalysisResult


def generate_loldrivers_yaml(
    result: AnalysisResult,
    author: str = "Driver Search Tool",
    verified: bool = False,
) -> str:
    """Generate LOLDrivers-compatible YAML entry."""
    driver = result.driver

    # Build known vulnerable samples list
    samples: list[dict[str, Any]] = [
        {
            "Filename": driver.original_filename or driver.name,
            "SHA256": driver.hashes.sha256,
        }
    ]

    if driver.hashes.sha1:
        samples[0]["SHA1"] = driver.hashes.sha1
    if driver.hashes.md5:
        samples[0]["MD5"] = driver.hashes.md5
    if driver.hashes.authentihash_sha256:
        samples[0]["Authentihash"] = {
            "SHA256": str(driver.hashes.authentihash_sha256),
        }
        if driver.hashes.authentihash_sha1:
            auth_hash: Any = samples[0]["Authentihash"]
            if isinstance(auth_hash, dict):
                auth_hash["SHA1"] = str(driver.hashes.authentihash_sha1)

    if driver.signature:
        samples[0]["Signature"] = driver.signature.signer
    if driver.vendor:
        samples[0]["Company"] = driver.vendor
    if driver.description:
        samples[0]["Description"] = str(driver.description)
    if driver.product_name:
        samples[0]["Product"] = str(driver.product_name)

    # Build vulnerability description
    vuln_descriptions: list[str] = []
    for vuln in result.vulnerabilities:
        vuln_descriptions.append(f"- {vuln.vuln_type.value}: {vuln.description}")

    description = driver.description or f"Vulnerable driver: {driver.name}"
    if vuln_descriptions:
        description += "\n\nDetected capabilities:\n" + "\n".join(vuln_descriptions)

    # Build the YAML structure
    entry: dict[str, Any] = {
        "Name": driver.original_filename or driver.name,
        "Description": description,
        "Author": author,
        "Created": datetime.now().strftime("%Y-%m-%d"),
        "MitreID": "T1068",  # Exploitation for Privilege Escalation
        "Category": "vulnerable driver",
        "Verified": "TRUE" if verified else "FALSE",
        "Commands": {
            "Command": f"sc.exe create {driver.internal_name or 'vuln_driver'} "
            f'binPath="C:\\Windows\\Temp\\{driver.name}" type=kernel && '
            f"sc.exe start {driver.internal_name or 'vuln_driver'}",
            "Description": "Load the vulnerable driver",
            "OperatingSystem": "Windows 10, Windows 11",
            "Privileges": "kernel",
            "Usecase": "Elevate privileges or bypass security controls",
        },
        "Resources": [],
        "Detection": [],
        "KnownVulnerableSamples": samples,
    }

    # Add CVE references if available
    for vuln in result.vulnerabilities:
        if vuln.cve_id:
            entry["Resources"].append(f"https://nvd.nist.gov/vuln/detail/{vuln.cve_id}")

    # Add notes
    if result.notes:
        entry["Acknowledgement"] = {"Handle": author, "Notes": result.notes}

    # Use safe_dump with proper formatting
    output_yaml: str = yaml.safe_dump(
        entry,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
        width=120,
    )
    return output_yaml


def generate_loldrivers_filename(result: AnalysisResult) -> str:
    """Generate appropriate filename for LOLDrivers YAML."""
    # Use first 8 chars of SHA256 and sanitized driver name
    sha_prefix = result.driver.hashes.sha256[:8]
    name = result.driver.original_filename or result.driver.name
    # Sanitize filename
    safe_name = "".join(c if c.isalnum() or c in ".-_" else "_" for c in name)
    safe_name = safe_name.replace(".sys", "").replace(".SYS", "")

    return f"{safe_name}_{sha_prefix}.yaml"
