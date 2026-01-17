"""SQLite persistence layer for driver research data."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

import aiosqlite

from driver_search.config import get_settings
from driver_search.models import (
    AnalysisResult,
    Driver,
    DriverHash,
    SignatureInfo,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS drivers (
    sha256 TEXT PRIMARY KEY,
    sha1 TEXT,
    md5 TEXT,
    authentihash_sha256 TEXT,
    authentihash_sha1 TEXT,
    imphash TEXT,
    name TEXT NOT NULL,
    file_path TEXT,
    file_size INTEGER,
    version TEXT,
    description TEXT,
    vendor TEXT,
    original_filename TEXT,
    product_name TEXT,
    internal_name TEXT,
    compile_time TEXT,
    signature_json TEXT,
    ioctls_json TEXT,
    imports_json TEXT,
    exports_json TEXT,
    sections_json TEXT,
    first_seen TEXT NOT NULL,
    source TEXT
);

CREATE TABLE IF NOT EXISTS analysis_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    driver_sha256 TEXT NOT NULL REFERENCES drivers(sha256),
    risk_level TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    in_loldrivers INTEGER NOT NULL DEFAULT 0,
    in_ms_blocklist INTEGER NOT NULL DEFAULT 0,
    vt_detections INTEGER,
    vt_total INTEGER,
    analysis_time TEXT NOT NULL,
    notes_json TEXT,
    dangerous_imports_json TEXT,
    UNIQUE(driver_sha256, analysis_time)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL REFERENCES analysis_results(id),
    vuln_type TEXT NOT NULL,
    description TEXT NOT NULL,
    cve_id TEXT,
    evidence TEXT,
    ioctl_code INTEGER,
    function_name TEXT,
    offset INTEGER,
    confidence REAL NOT NULL DEFAULT 1.0
);

CREATE TABLE IF NOT EXISTS loldrivers_hashes (
    sha256 TEXT PRIMARY KEY,
    name TEXT,
    category TEXT,
    last_synced TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_entries (
    cve_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    published TEXT NOT NULL,
    modified TEXT NOT NULL,
    cvss_score REAL,
    cvss_vector TEXT,
    references_json TEXT,
    affected_products_json TEXT,
    cwe_ids_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_drivers_vendor ON drivers(vendor);
CREATE INDEX IF NOT EXISTS idx_drivers_first_seen ON drivers(first_seen);
CREATE INDEX IF NOT EXISTS idx_analysis_risk ON analysis_results(risk_level, risk_score);
CREATE INDEX IF NOT EXISTS idx_vulns_type ON vulnerabilities(vuln_type);
CREATE INDEX IF NOT EXISTS idx_cve_published ON cve_entries(published);
"""


class Database:
    """Async SQLite database wrapper."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or get_settings().output.db_path
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        """Connect to database and initialize schema."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(SCHEMA)
        await self._conn.commit()

    async def close(self) -> None:
        """Close database connection."""
        if self._conn:
            await self._conn.close()
            self._conn = None

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[aiosqlite.Connection]:
        """Context manager for transactions."""
        if not self._conn:
            raise RuntimeError("Database not connected")
        try:
            yield self._conn
            await self._conn.commit()
        except Exception:
            await self._conn.rollback()
            raise

    async def save_driver(self, driver: Driver) -> None:
        """Save or update a driver."""
        if not self._conn:
            raise RuntimeError("Database not connected")

        signature_json = None
        if driver.signature:
            signature_json = json.dumps(
                {
                    "signer": driver.signature.signer,
                    "issuer": driver.signature.issuer,
                    "serial_number": driver.signature.serial_number,
                    "valid_from": driver.signature.valid_from.isoformat(),
                    "valid_to": driver.signature.valid_to.isoformat(),
                    "is_valid": driver.signature.is_valid,
                    "is_expired": driver.signature.is_expired,
                    "certificate_chain": list(driver.signature.certificate_chain),
                }
            )

        ioctls_json = json.dumps(
            [
                {
                    "code": i.code,
                    "device_type": i.device_type,
                    "function": i.function,
                    "method": i.method,
                    "access": i.access,
                    "handler_address": i.handler_address,
                    "suspicious_calls": list(i.suspicious_calls),
                }
                for i in driver.ioctls
            ]
        )

        await self._conn.execute(
            """
            INSERT OR REPLACE INTO drivers (
                sha256, sha1, md5, authentihash_sha256, authentihash_sha1, imphash,
                name, file_path, file_size, version, description, vendor,
                original_filename, product_name, internal_name, compile_time,
                signature_json, ioctls_json, imports_json, exports_json,
                sections_json, first_seen, source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                driver.hashes.sha256,
                driver.hashes.sha1,
                driver.hashes.md5,
                driver.hashes.authentihash_sha256,
                driver.hashes.authentihash_sha1,
                driver.hashes.imphash,
                driver.name,
                driver.file_path,
                driver.file_size,
                driver.version,
                driver.description,
                driver.vendor,
                driver.original_filename,
                driver.product_name,
                driver.internal_name,
                driver.compile_time.isoformat() if driver.compile_time else None,
                signature_json,
                ioctls_json,
                json.dumps(driver.imports),
                json.dumps(driver.exports),
                json.dumps(driver.sections),
                driver.first_seen.isoformat(),
                driver.source,
            ),
        )
        await self._conn.commit()

    async def get_driver(self, sha256: str) -> Driver | None:
        """Get a driver by SHA256 hash."""
        if not self._conn:
            raise RuntimeError("Database not connected")

        cursor = await self._conn.execute(
            "SELECT * FROM drivers WHERE sha256 = ?",
            (sha256,),
        )
        row = await cursor.fetchone()
        if not row:
            return None

        return self._row_to_driver(row)

    async def driver_exists(self, sha256: str) -> bool:
        """Check if a driver exists in the database."""
        if not self._conn:
            raise RuntimeError("Database not connected")

        cursor = await self._conn.execute(
            "SELECT 1 FROM drivers WHERE sha256 = ?",
            (sha256,),
        )
        return await cursor.fetchone() is not None

    async def get_drivers_by_vendor(self, vendor: str) -> list[Driver]:
        """Get all drivers from a specific vendor."""
        if not self._conn:
            raise RuntimeError("Database not connected")

        cursor = await self._conn.execute(
            "SELECT * FROM drivers WHERE vendor LIKE ?",
            (f"%{vendor}%",),
        )
        rows = await cursor.fetchall()
        return [self._row_to_driver(row) for row in rows]

    async def save_analysis_result(self, result: AnalysisResult) -> int:
        """Save analysis result and return ID."""
        if not self._conn:
            raise RuntimeError("Database not connected")

        # Ensure driver is saved first
        await self.save_driver(result.driver)

        cursor = await self._conn.execute(
            """
            INSERT INTO analysis_results (
                driver_sha256, risk_level, risk_score, in_loldrivers,
                in_ms_blocklist, vt_detections, vt_total, analysis_time,
                notes_json, dangerous_imports_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.driver.hashes.sha256,
                result.risk_level.value,
                result.risk_score,
                int(result.in_loldrivers),
                int(result.in_ms_blocklist),
                result.vt_detections,
                result.vt_total,
                result.analysis_time.isoformat(),
                json.dumps(result.notes),
                json.dumps(result.dangerous_imports),
            ),
        )
        analysis_id = cursor.lastrowid
        assert analysis_id is not None

        # Save vulnerabilities
        for vuln in result.vulnerabilities:
            await self._conn.execute(
                """
                INSERT INTO vulnerabilities (
                    analysis_id, vuln_type, description, cve_id, evidence,
                    ioctl_code, function_name, offset, confidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    analysis_id,
                    vuln.vuln_type.value,
                    vuln.description,
                    vuln.cve_id,
                    vuln.evidence,
                    vuln.ioctl_code,
                    vuln.function_name,
                    vuln.offset,
                    vuln.confidence,
                ),
            )

        await self._conn.commit()
        return analysis_id

    async def is_in_loldrivers(self, sha256: str) -> bool:
        """Check if hash is in LOLDrivers database."""
        if not self._conn:
            raise RuntimeError("Database not connected")

        cursor = await self._conn.execute(
            "SELECT 1 FROM loldrivers_hashes WHERE sha256 = ?",
            (sha256.lower(),),
        )
        return await cursor.fetchone() is not None

    async def save_loldrivers_hash(
        self,
        sha256: str,
        name: str | None = None,
        category: str | None = None,
    ) -> None:
        """Save a LOLDrivers hash."""
        if not self._conn:
            raise RuntimeError("Database not connected")

        await self._conn.execute(
            """
            INSERT OR REPLACE INTO loldrivers_hashes (sha256, name, category, last_synced)
            VALUES (?, ?, ?, ?)
            """,
            (sha256.lower(), name, category, datetime.now().isoformat()),
        )
        await self._conn.commit()

    async def get_stats(self) -> dict[str, int]:
        """Get database statistics."""
        if not self._conn:
            raise RuntimeError("Database not connected")

        stats: dict[str, int] = {}

        cursor = await self._conn.execute("SELECT COUNT(*) FROM drivers")
        row = await cursor.fetchone()
        stats["drivers"] = row[0] if row else 0

        cursor = await self._conn.execute("SELECT COUNT(*) FROM analysis_results")
        row = await cursor.fetchone()
        stats["analyses"] = row[0] if row else 0

        cursor = await self._conn.execute("SELECT COUNT(*) FROM vulnerabilities")
        row = await cursor.fetchone()
        stats["vulnerabilities"] = row[0] if row else 0

        cursor = await self._conn.execute("SELECT COUNT(*) FROM loldrivers_hashes")
        row = await cursor.fetchone()
        stats["loldrivers_hashes"] = row[0] if row else 0

        cursor = await self._conn.execute(
            "SELECT COUNT(*) FROM analysis_results WHERE risk_level = 'critical'"
        )
        row = await cursor.fetchone()
        stats["critical_risk"] = row[0] if row else 0

        return stats

    def _row_to_driver(self, row: aiosqlite.Row) -> Driver:
        """Convert database row to Driver object."""
        signature = None
        if row["signature_json"]:
            sig_data = json.loads(row["signature_json"])
            signature = SignatureInfo(
                signer=sig_data["signer"],
                issuer=sig_data["issuer"],
                serial_number=sig_data["serial_number"],
                valid_from=datetime.fromisoformat(sig_data["valid_from"]),
                valid_to=datetime.fromisoformat(sig_data["valid_to"]),
                is_valid=sig_data["is_valid"],
                is_expired=sig_data["is_expired"],
                certificate_chain=tuple(sig_data.get("certificate_chain", [])),
            )

        ioctls = []
        if row["ioctls_json"]:
            from driver_search.models import IOCTLInfo

            for i_data in json.loads(row["ioctls_json"]):
                ioctls.append(
                    IOCTLInfo(
                        code=i_data["code"],
                        device_type=i_data["device_type"],
                        function=i_data["function"],
                        method=i_data["method"],
                        access=i_data["access"],
                        handler_address=i_data.get("handler_address"),
                        suspicious_calls=tuple(i_data.get("suspicious_calls", [])),
                    )
                )

        return Driver(
            name=row["name"],
            hashes=DriverHash(
                sha256=row["sha256"],
                sha1=row["sha1"],
                md5=row["md5"],
                authentihash_sha256=row["authentihash_sha256"],
                authentihash_sha1=row["authentihash_sha1"],
                imphash=row["imphash"] if "imphash" in row else None,  # noqa: SIM401
            ),
            file_path=row["file_path"],
            file_size=row["file_size"],
            signature=signature,
            version=row["version"],
            description=row["description"],
            vendor=row["vendor"],
            original_filename=row["original_filename"],
            product_name=row["product_name"],
            internal_name=row["internal_name"],
            compile_time=datetime.fromisoformat(row["compile_time"])
            if row["compile_time"]
            else None,
            ioctls=ioctls,
            imports=json.loads(row["imports_json"]) if row["imports_json"] else [],
            exports=json.loads(row["exports_json"]) if row["exports_json"] else [],
            sections=json.loads(row["sections_json"]) if row["sections_json"] else [],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            source=row["source"],
        )


@asynccontextmanager
async def get_database(db_path: Path | None = None) -> AsyncIterator[Database]:
    """Context manager for database access."""
    db = Database(db_path)
    await db.connect()
    try:
        yield db
    finally:
        await db.close()
