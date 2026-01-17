"""PE file analysis for driver binaries."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from driver_search.models import (
    DANGEROUS_IMPORTS,
    Driver,
    IOCTLInfo,
    SignatureInfo,
    Vulnerability,
    VulnerabilityType,
)
from driver_search.utils.hashing import compute_full_hashes

if TYPE_CHECKING:
    import pefile


@dataclass
class PEAnalysisResult:
    """Result of PE file analysis."""

    driver: Driver
    dangerous_imports: list[str] = field(default_factory=list)
    suspicious_strings: list[str] = field(default_factory=list)
    potential_vulns: list[Vulnerability] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def analyze_pe(file_path: str | Path) -> PEAnalysisResult:
    """Analyze a PE file for driver characteristics and vulnerabilities."""
    import pefile as pe_module

    path = Path(file_path)
    hashes = compute_full_hashes(path)

    # Create initial driver object
    driver = Driver(
        name=path.name,
        hashes=hashes,
        file_path=str(path.absolute()),
        file_size=path.stat().st_size,
    )

    result = PEAnalysisResult(driver=driver)

    try:
        pe = pe_module.PE(str(path), fast_load=False)

        # Calculate and update imphash
        driver.hashes = replace(driver.hashes, imphash=pe.get_imphash())

        _analyze_pe_headers(pe, driver, result)
        _analyze_imports(pe, driver, result)
        _analyze_exports(pe, driver, result)
        _analyze_sections(pe, driver, result)
        _analyze_signature(path, driver)
        _detect_ioctl_patterns(pe, driver, result)
        _run_ioctl_disassembly(pe, driver, result)
        pe.close()
    except Exception as e:
        result.errors.append(f"PE parsing error: {e}")

    return result


def _analyze_pe_headers(pe: pefile.PE, driver: Driver, result: PEAnalysisResult) -> None:
    """Extract information from PE headers."""
    # Compile timestamp
    try:
        timestamp = pe.FILE_HEADER.TimeDateStamp
        driver.compile_time = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except Exception:
        pass

    # Version info
    if hasattr(pe, "FileInfo"):
        for file_info in pe.FileInfo:
            if hasattr(file_info, "__iter__"):
                for info in file_info:
                    if hasattr(info, "StringTable"):
                        for st in info.StringTable:
                            for key, value in st.entries.items():
                                key_str = key.decode("utf-8", errors="ignore")
                                value_str = value.decode("utf-8", errors="ignore")

                                if key_str == "FileDescription":
                                    driver.description = value_str
                                elif key_str == "FileVersion":
                                    driver.version = value_str
                                elif key_str == "CompanyName":
                                    driver.vendor = value_str
                                elif key_str == "OriginalFilename":
                                    driver.original_filename = value_str
                                elif key_str == "ProductName":
                                    driver.product_name = value_str
                                elif key_str == "InternalName":
                                    driver.internal_name = value_str


def _analyze_imports(pe: pefile.PE, driver: Driver, result: PEAnalysisResult) -> None:
    """Analyze PE imports for dangerous functions."""
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode("utf-8", errors="ignore")

        for imp in entry.imports:
            if imp.name:
                func_name = imp.name.decode("utf-8", errors="ignore")
                driver.imports.append(f"{dll_name}!{func_name}")

                # Check for dangerous imports
                if func_name in DANGEROUS_IMPORTS:
                    result.dangerous_imports.append(func_name)

                    # Create potential vulnerability
                    vuln_type = _import_to_vuln_type(func_name)
                    if vuln_type:
                        result.potential_vulns.append(
                            Vulnerability(
                                vuln_type=vuln_type,
                                description=f"Driver imports {func_name}",
                                function_name=func_name,
                                confidence=0.7,  # Import alone isn't definitive
                            )
                        )


def _analyze_exports(pe: pefile.PE, driver: Driver, result: PEAnalysisResult) -> None:
    """Analyze PE exports."""
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name:
            driver.exports.append(exp.name.decode("utf-8", errors="ignore"))


def _analyze_sections(pe: pefile.PE, driver: Driver, result: PEAnalysisResult) -> None:
    """Analyze PE sections."""
    for section in pe.sections:
        name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
        driver.sections.append(name)


def _analyze_signature(file_path: Path, driver: Driver) -> None:
    """Extract Authenticode signature information."""
    try:
        from signify.authenticode import SignedPEFile  # type: ignore[attr-defined]

        with open(file_path, "rb") as f:
            signed_pe = SignedPEFile(f)

            for signed_data in signed_pe.signed_datas:
                if signed_data.signer_info:
                    cert = signed_data.signer_info.signing_cert

                    driver.signature = SignatureInfo(
                        signer=cert.subject.dn if cert.subject else "Unknown",
                        issuer=cert.issuer.dn if cert.issuer else "Unknown",
                        serial_number=str(cert.serial_number),
                        valid_from=cert.valid_from,
                        valid_to=cert.valid_to,
                        is_valid=True,  # signify would raise on invalid
                        is_expired=cert.valid_to < datetime.now(timezone.utc),
                    )
                    break  # Just use first signature
    except ImportError:
        pass  # signify not available
    except Exception:
        pass  # Signature parsing failed (might be unsigned)


def _detect_ioctl_patterns(
    pe: pefile.PE,
    driver: Driver,
    result: PEAnalysisResult,
) -> None:
    """Detect IOCTL handler patterns in the driver.

    This is a heuristic approach - looks for common IOCTL dispatch patterns.
    Real analysis would require more sophisticated techniques.
    """
    # Look for common IOCTL codes in the binary
    # This is a simplified approach - production would use disassembly

    try:
        data = pe.get_memory_mapped_image()
    except Exception:
        return

    # Common dangerous IOCTL patterns
    dangerous_patterns = [
        # Physical memory mapping IOCTLs
        (b"\x22\x00\x00\x00", "Physical memory"),  # Device type for physical memory
        # Common hardware utility patterns
        (b"\\Device\\PhysicalMemory", "PhysicalMemory access"),
        (b"MmMapIoSpace", "IO space mapping"),
        (b"READ_PORT_", "Port I/O"),
        (b"WRITE_PORT_", "Port I/O"),
    ]

    for pattern, description in dangerous_patterns:
        if pattern in data:
            result.suspicious_strings.append(f"{description}: found pattern")


def _import_to_vuln_type(import_name: str) -> VulnerabilityType | None:
    """Map import name to vulnerability type."""
    mappings: dict[str, VulnerabilityType] = {
        "MmMapIoSpace": VulnerabilityType.PHYSICAL_MEMORY_READ,
        "MmUnmapIoSpace": VulnerabilityType.PHYSICAL_MEMORY_READ,
        "MmMapIoSpaceEx": VulnerabilityType.PHYSICAL_MEMORY_READ,
        "__readmsr": VulnerabilityType.MSR_READ,
        "__writemsr": VulnerabilityType.MSR_WRITE,
        "IoAllocateMdl": VulnerabilityType.MDL_MAPPING,
        "MmMapLockedPages": VulnerabilityType.MDL_MAPPING,
        "MmMapLockedPagesSpecifyCache": VulnerabilityType.MDL_MAPPING,
        "ZwMapViewOfSection": VulnerabilityType.PHYSICAL_MEMORY_READ,
        "__inbyte": VulnerabilityType.PORT_IO,
        "__outbyte": VulnerabilityType.PORT_IO,
        "READ_PORT_UCHAR": VulnerabilityType.PORT_IO,
        "WRITE_PORT_UCHAR": VulnerabilityType.PORT_IO,
        "HalGetBusDataByOffset": VulnerabilityType.PCI_CONFIG,
        "HalSetBusDataByOffset": VulnerabilityType.PCI_CONFIG,
        "MmCopyVirtualMemory": VulnerabilityType.ARBITRARY_KERNEL_READ,
        "ZwReadVirtualMemory": VulnerabilityType.ARBITRARY_KERNEL_READ,
        "ZwWriteVirtualMemory": VulnerabilityType.ARBITRARY_KERNEL_WRITE,
    }
    return mappings.get(import_name)


def calculate_risk_score(result: PEAnalysisResult, in_loldrivers: bool = False) -> int:
    """Calculate risk score based on analysis results."""
    score = 0

    # Dangerous imports
    for imp in result.dangerous_imports:
        if imp in ("MmMapIoSpace", "MmMapIoSpaceEx"):
            score += 50  # Physical memory R/W is critical
        elif imp in ("__readmsr", "__writemsr"):
            score += 40  # MSR access
        elif imp.startswith(("__in", "__out", "READ_PORT", "WRITE_PORT")):
            score += 20  # Port I/O
        elif imp.startswith("Mm") or imp.startswith("Zw"):
            score += 30  # Other memory operations
        else:
            score += 10  # Other dangerous imports

    # Signed by major vendor
    if result.driver.signature and result.driver.vendor:
        vendor_lower = result.driver.vendor.lower()
        major_vendors = ["asus", "msi", "gigabyte", "intel", "amd", "nvidia", "dell", "hp"]
        if any(v in vendor_lower for v in major_vendors):
            score += 20

    # Not in LOLDrivers (blocklist gap)
    if not in_loldrivers:
        score += 30

    # Recent driver
    if result.driver.compile_time:
        age_days = (datetime.now(timezone.utc) - result.driver.compile_time).days
        if age_days < 365:
            score += 10

    # Cap at 100
    return min(score, 100)


def _run_ioctl_disassembly(
    pe: pefile.PE,
    driver: Driver,
    result: PEAnalysisResult,
) -> None:
    """Run IOCTL disassembly analysis if capstone is available."""
    try:
        from driver_search.analysis.disasm import analyze_driver_ioctls
    except ImportError:
        return  # Capstone not available

    try:
        ioctl_result = analyze_driver_ioctls(pe)

        # Convert IOCTL codes to IOCTLInfo objects
        for code in ioctl_result.ioctl_codes:
            driver.ioctls.append(
                IOCTLInfo(
                    code=code.raw,
                    device_type=code.device_type,
                    function=code.function,
                    method=code.method.value,
                    access=code.access.value,
                )
            )

        # Add vulnerabilities from disassembly
        for vuln_desc in ioctl_result.vulnerabilities:
            # Determine vulnerability type from description
            if "MSR" in vuln_desc:
                vuln_type = VulnerabilityType.MSR_WRITE
            elif "Port I/O" in vuln_desc:
                vuln_type = VulnerabilityType.PORT_IO
            elif "Control register" in vuln_desc:
                vuln_type = VulnerabilityType.ARBITRARY_KERNEL_WRITE
            elif "METHOD_NEITHER" in vuln_desc:
                vuln_type = VulnerabilityType.ARBITRARY_KERNEL_READ
            else:
                vuln_type = VulnerabilityType.UNKNOWN

            result.potential_vulns.append(
                Vulnerability(
                    vuln_type=vuln_type,
                    description=vuln_desc,
                    confidence=0.85,  # Disassembly-based detection is more reliable
                )
            )

        # Add suspicious patterns to strings
        for pattern_name, addr, context in ioctl_result.dangerous_patterns:
            result.suspicious_strings.append(f"Disasm: {pattern_name} at 0x{addr:X} ({context})")

    except Exception as e:
        result.errors.append(f"IOCTL disassembly error: {e}")
