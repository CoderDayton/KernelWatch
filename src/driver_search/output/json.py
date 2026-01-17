"""JSON output formatter for CLI commands (sidecar mode)."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any


class JSONEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles dataclasses and special types."""

    def default(self, obj: Any) -> Any:
        if is_dataclass(obj) and not isinstance(obj, type):
            return asdict(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, bytes):
            return obj.hex()
        return super().default(obj)


def to_json(obj: Any, pretty: bool = False) -> str:
    """Convert object to JSON string."""
    indent = 2 if pretty else None
    return json.dumps(obj, cls=JSONEncoder, indent=indent)


def analysis_result_to_dict(result: Any) -> dict[str, Any]:
    """Convert AnalysisResult to JSON-serializable dict."""
    driver = result.driver

    return {
        "driver": {
            "name": driver.name,
            "hashes": {
                "sha256": driver.hashes.sha256,
                "sha1": driver.hashes.sha1,
                "md5": driver.hashes.md5,
                "authentihash_sha256": driver.hashes.authentihash_sha256,
            },
            "vendor": driver.vendor,
            "version": driver.version,
            "description": driver.description,
            "signer": driver.signature.signer if driver.signature else None,
            "compile_time": driver.compile_time.isoformat() if driver.compile_time else None,
        },
        "vulnerabilities": [
            {
                "vuln_type": v.vuln_type.value,
                "description": v.description,
                "cve_id": v.cve_id,
                "confidence": v.confidence,
            }
            for v in result.vulnerabilities
        ],
        "risk_level": result.risk_level.value,
        "risk_score": result.risk_score,
        "in_loldrivers": result.in_loldrivers,
        "in_ms_blocklist": result.in_ms_blocklist,
        "vt_detections": result.vt_detections,
        "vt_total": result.vt_total,
        "dangerous_imports": result.dangerous_imports,
        "notes": result.notes,
    }


def stats_to_dict(stats: dict[str, int]) -> dict[str, Any]:
    """Format stats for JSON output."""
    return {
        "drivers": stats.get("drivers", 0),
        "analyses": stats.get("analyses", 0),
        "vulnerabilities": stats.get("vulnerabilities", 0),
        "loldrivers_hashes": stats.get("loldrivers_hashes", 0),
        "critical_risk": stats.get("critical_risk", 0),
    }


def cve_entries_to_list(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Format CVE entries for JSON output."""
    return [
        {
            "cve_id": e.get("cve_id", ""),
            "description": e.get("description", ""),
            "published": e.get("published", ""),
            "cvss_score": e.get("cvss_score"),
            "cvss_vector": e.get("cvss_vector"),
        }
        for e in entries
    ]
