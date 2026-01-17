"""Hashing utilities for driver binaries."""

from __future__ import annotations

import hashlib
from pathlib import Path

from driver_search.models import DriverHash


def compute_hashes(file_path: str | Path) -> DriverHash:
    """Compute SHA256, SHA1, and MD5 hashes for a file."""
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()  # noqa: S324
    md5 = hashlib.md5()  # noqa: S324

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)

    return DriverHash(
        sha256=sha256.hexdigest(),
        sha1=sha1.hexdigest(),
        md5=md5.hexdigest(),
    )


def compute_hashes_from_bytes(data: bytes) -> DriverHash:
    """Compute hashes from bytes."""
    return DriverHash(
        sha256=hashlib.sha256(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),  # noqa: S324
        md5=hashlib.md5(data).hexdigest(),  # noqa: S324
    )


def compute_authentihash(file_path: str | Path) -> tuple[str, str] | None:
    """
    Compute Authenticode hash (SHA256 and SHA1).

    The Authenticode hash excludes the PE signature from the hash calculation.
    Returns (sha256, sha1) tuple or None if not a valid PE.
    """
    try:
        from signify import fingerprinter
    except ImportError:
        return None

    try:
        with open(file_path, "rb") as f:
            fpr = fingerprinter.AuthenticodeFingerprinter(f)  # type: ignore
            fpr.add_authenticode_hashers(hashlib.sha256, hashlib.sha1)
            results = fpr.hash()

        sha256_hash = None
        sha1_hash = None
        for result in results:
            if result["name"] == "sha256":
                sha256_hash = result["digest"].hex()
            elif result["name"] == "sha1":
                sha1_hash = result["digest"].hex()

        if sha256_hash and sha1_hash:
            return (sha256_hash, sha1_hash)
    except Exception:
        pass

    return None


def compute_full_hashes(file_path: str | Path) -> DriverHash:
    """Compute all hashes including Authenticode."""
    base_hashes = compute_hashes(file_path)
    auth_hashes = compute_authentihash(file_path)

    if auth_hashes:
        return DriverHash(
            sha256=base_hashes.sha256,
            sha1=base_hashes.sha1,
            md5=base_hashes.md5,
            authentihash_sha256=auth_hashes[0],
            authentihash_sha1=auth_hashes[1],
        )
    return base_hashes
