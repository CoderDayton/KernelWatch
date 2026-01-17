"""Core data models for driver research."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class VulnerabilityType(Enum):
    """Types of dangerous driver capabilities."""

    PHYSICAL_MEMORY_READ = "physical_memory_read"
    PHYSICAL_MEMORY_WRITE = "physical_memory_write"
    MSR_READ = "msr_read"
    MSR_WRITE = "msr_write"
    PORT_IO = "port_io"
    PCI_CONFIG = "pci_config"
    ARBITRARY_KERNEL_READ = "arbitrary_kernel_read"
    ARBITRARY_KERNEL_WRITE = "arbitrary_kernel_write"
    MDL_MAPPING = "mdl_mapping"
    UNKNOWN = "unknown"


class RiskLevel(Enum):
    """Risk assessment level."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True, slots=True)
class DriverHash:
    """Hash values for a driver binary."""

    sha256: str
    sha1: str | None = None
    md5: str | None = None
    authentihash_sha256: str | None = None
    authentihash_sha1: str | None = None
    imphash: str | None = None


@dataclass(frozen=True, slots=True)
class SignatureInfo:
    """Authenticode signature information."""

    signer: str
    issuer: str
    serial_number: str
    valid_from: datetime
    valid_to: datetime
    is_valid: bool
    is_expired: bool
    certificate_chain: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class IOCTLInfo:
    """Information about a driver IOCTL handler."""

    code: int
    device_type: int
    function: int
    method: int
    access: int
    handler_address: int | None = None
    suspicious_calls: tuple[str, ...] = field(default_factory=tuple)

    @property
    def code_hex(self) -> str:
        """Return IOCTL code as hex string."""
        return f"0x{self.code:08X}"


@dataclass(slots=True)
class Driver:
    """Represents a Windows kernel driver."""

    name: str
    hashes: DriverHash
    file_path: str | None = None
    file_size: int | None = None
    signature: SignatureInfo | None = None
    version: str | None = None
    description: str | None = None
    vendor: str | None = None
    original_filename: str | None = None
    product_name: str | None = None
    internal_name: str | None = None
    compile_time: datetime | None = None
    ioctls: list[IOCTLInfo] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    source: str | None = None

    def __hash__(self) -> int:
        return hash(self.hashes.sha256)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Driver):
            return NotImplemented
        return self.hashes.sha256 == other.hashes.sha256


@dataclass(slots=True)
class Vulnerability:
    """Represents a vulnerability associated with a driver."""

    vuln_type: VulnerabilityType
    description: str
    cve_id: str | None = None
    evidence: str | None = None
    ioctl_code: int | None = None
    function_name: str | None = None
    offset: int | None = None
    confidence: float = 1.0


@dataclass(slots=True)
class AnalysisResult:
    """Result of analyzing a driver for vulnerabilities."""

    driver: Driver
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.INFO
    risk_score: int = 0
    in_loldrivers: bool = False
    in_ms_blocklist: bool = False
    vt_detections: int | None = None
    vt_total: int | None = None
    analysis_time: datetime = field(default_factory=datetime.now)
    notes: list[str] = field(default_factory=list)
    dangerous_imports: list[str] = field(default_factory=list)

    @property
    def is_known_vulnerable(self) -> bool:
        """Check if driver is already in known blocklists."""
        return self.in_loldrivers or self.in_ms_blocklist

    @property
    def detection_ratio(self) -> str | None:
        """Return VT detection ratio string."""
        if self.vt_detections is not None and self.vt_total is not None:
            return f"{self.vt_detections}/{self.vt_total}"
        return None


@dataclass(frozen=True, slots=True)
class CVEEntry:
    """CVE information from NVD."""

    cve_id: str
    description: str
    published: datetime
    modified: datetime
    cvss_score: float | None = None
    cvss_vector: str | None = None
    references: tuple[str, ...] = field(default_factory=tuple)
    affected_products: tuple[str, ...] = field(default_factory=tuple)
    cwe_ids: tuple[str, ...] = field(default_factory=tuple)


# Dangerous Windows kernel imports that indicate potential vulnerabilities
DANGEROUS_IMPORTS: frozenset[str] = frozenset(
    {
        # Physical memory access
        "MmMapIoSpace",
        "MmUnmapIoSpace",
        "MmMapIoSpaceEx",
        # MSR access
        "__readmsr",
        "__writemsr",
        # MDL operations
        "IoAllocateMdl",
        "MmMapLockedPages",
        "MmMapLockedPagesSpecifyCache",
        "MmBuildMdlForNonPagedPool",
        "MmProbeAndLockPages",
        # Section mapping
        "ZwMapViewOfSection",
        "ZwOpenSection",
        # Port I/O
        "__inbyte",
        "__inword",
        "__indword",
        "__outbyte",
        "__outword",
        "__outdword",
        "READ_PORT_UCHAR",
        "WRITE_PORT_UCHAR",
        # PCI config
        "HalGetBusDataByOffset",
        "HalSetBusDataByOffset",
        # Process memory
        "MmCopyVirtualMemory",
        "ZwReadVirtualMemory",
        "ZwWriteVirtualMemory",
        # Other dangerous
        "ExAllocatePool",  # Deprecated but still concerning
        "KeInsertQueueApc",
        "KeInitializeApc",
    }
)

# Keywords for NVD search
NVD_KEYWORDS: tuple[str, ...] = (
    "motherboard",
    "overclock",
    "hardware monitor",
    "tuning utility",
    "bios update",
    "system utility",
    "rgb control",
    "fan control",
    "driver privilege",
    "kernel driver",
)

# Known vulnerable driver vendors (prioritize monitoring)
PRIORITY_VENDORS: tuple[str, ...] = (
    "ASUSTeK",
    "ASUS",
    "MSI",
    "Micro-Star",
    "GIGABYTE",
    "Giga-Byte",
    "Intel",
    "AMD",
    "NVIDIA",
    "Razer",
    "Corsair",
    "EVGA",
    "NZXT",
    "Thermaltake",
    "ASRock",
    "Biostar",
    "Dell",
    "HP",
    "Lenovo",
)
