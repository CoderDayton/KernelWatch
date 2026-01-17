"""YARA rule generator for driver detection."""

from __future__ import annotations

import re
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from driver_search.models import AnalysisResult


def generate_yara_rule(result: AnalysisResult) -> str:
    """Generate a YARA rule for detecting the analyzed driver."""
    driver = result.driver

    # Sanitize name for rule identifier
    safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", driver.name or "unknown_driver")
    if safe_name[0].isdigit():
        safe_name = f"driver_{safe_name}"

    rule_name = f"suspicious_driver_{safe_name}"
    date_str = datetime.now().strftime("%Y-%m-%d")

    conditions = []

    # 1. Hash match (strongest)
    if driver.hashes.sha256:
        conditions.append(f'hash.sha256(0, filesize) == "{driver.hashes.sha256}"')

    # 2. Authentihash (for signed variants)
    if driver.hashes.authentihash_sha256:
        conditions.append(
            f"// Authentihash: {driver.hashes.authentihash_sha256}\n"
            f'        pe.authentihash() == "{driver.hashes.authentihash_sha256}"'
        )

    # 3. Imphash (for similar builds)
    if driver.hashes.imphash:
        conditions.append(f'pe.imphash() == "{driver.hashes.imphash}"')

    # 4. Signature signer
    if driver.signature:
        # Escape quotes in signer name
        signer = driver.signature.signer.replace('"', '\\"')
        conditions.append(
            f'// Signer: {signer}\n        pe.signatures[0].subject contains "{signer}"'
        )

    # 5. Dangerous imports (heuristic)
    heuristic_conditions = []
    if result.dangerous_imports:
        for imp in result.dangerous_imports:
            if "!" in imp:
                dll, func = imp.split("!")
                heuristic_conditions.append(f'pe.imports("{dll}", "{func}")')
            else:
                # Fallback if dll not parsed
                pass

    # Join conditions with proper indentation
    condition_str = " or \n            ".join(conditions)
    file_size_limit = (driver.file_size or 10000000) + 1024

    rule = f"""import "pe"
import "hash"

rule {rule_name} : vulnerable_driver {{
    meta:
        description = "Detects vulnerable driver {driver.name}"
        author = "Driver Search Tool"
        date = "{date_str}"
        sha256 = "{driver.hashes.sha256}"
        risk_score = {result.risk_score}

    strings:
        $s1 = "{driver.original_filename or driver.name}" wide ascii

    condition:
        uint16(0) == 0x5A4D and filesize < {file_size_limit} and
        (
            {condition_str}
        )
}}"""

    return rule
