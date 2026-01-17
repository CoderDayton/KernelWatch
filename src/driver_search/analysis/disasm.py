"""IOCTL handler disassembly and analysis using Capstone."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pefile

# IOCTL code components
# CTL_CODE(DeviceType, Function, Method, Access)
# = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method


class IOCTLMethod(IntEnum):
    """IOCTL transfer method."""

    BUFFERED = 0
    IN_DIRECT = 1
    OUT_DIRECT = 2
    NEITHER = 3


class IOCTLAccess(IntEnum):
    """IOCTL access requirements."""

    ANY = 0
    READ = 1
    WRITE = 2
    READ_WRITE = 3


# Common device types for vulnerable drivers
DEVICE_TYPES = {
    0x00000022: "FILE_DEVICE_UNKNOWN",
    0x00000009: "FILE_DEVICE_DISK",
    0x0000001C: "FILE_DEVICE_PHYSICAL_NETCARD",
    0x00000027: "FILE_DEVICE_KSEC",
    0x00000032: "FILE_DEVICE_INFINIBAND",
    0x00009C40: "IOCTL_RWDRV",  # Common in hardware utilities
    0x0000A000: "IOCTL_PHYMEM",  # Physical memory drivers
}

# Dangerous x64 instruction patterns
DANGEROUS_PATTERNS = {
    # MSR access
    b"\x0f\x32": "rdmsr",  # Read MSR
    b"\x0f\x30": "wrmsr",  # Write MSR
    # Port I/O
    b"\xec": "in al, dx",
    b"\xed": "in eax, dx",
    b"\xee": "out dx, al",
    b"\xef": "out dx, eax",
    b"\xe4": "in al, imm8",
    b"\xe5": "in eax, imm8",
    b"\xe6": "out imm8, al",
    b"\xe7": "out imm8, eax",
    # CR access (ring 0 only)
    b"\x0f\x20": "mov reg, crN",
    b"\x0f\x22": "mov crN, reg",
    # Interrupts (can be used for exploits)
    b"\xcd\x2e": "int 0x2e",  # Legacy syscall
}

# Common function names that handle IOCTLs
IOCTL_HANDLER_NAMES = [
    "DeviceControl",
    "IoctlHandler",
    "DeviceIoControl",
    "DispatchDeviceControl",
    "HandleIoctl",
    "ProcessIoctl",
]


@dataclass
class DisassembledFunction:
    """Represents a disassembled function."""

    name: str
    address: int
    size: int
    instructions: list[tuple[int, str, str, bytes]] = field(default_factory=list)
    dangerous_instructions: list[tuple[int, str, str]] = field(default_factory=list)
    called_functions: list[int] = field(default_factory=list)
    called_imports: list[str] = field(default_factory=list)


@dataclass
class IOCTLCode:
    """Parsed IOCTL code."""

    raw: int
    device_type: int
    function: int
    method: IOCTLMethod
    access: IOCTLAccess

    @classmethod
    def from_raw(cls, code: int) -> IOCTLCode:
        """Parse raw IOCTL code into components."""
        device_type = (code >> 16) & 0xFFFF
        access = IOCTLAccess((code >> 14) & 0x3)
        function = (code >> 2) & 0xFFF
        method = IOCTLMethod(code & 0x3)
        return cls(
            raw=code,
            device_type=device_type,
            function=function,
            method=method,
            access=access,
        )

    @property
    def device_type_name(self) -> str:
        """Get human-readable device type."""
        return DEVICE_TYPES.get(self.device_type, f"0x{self.device_type:04X}")

    def __str__(self) -> str:
        return (
            f"IOCTL(0x{self.raw:08X}): "
            f"Device={self.device_type_name}, "
            f"Function=0x{self.function:03X}, "
            f"Method={self.method.name}, "
            f"Access={self.access.name}"
        )


@dataclass
class IOCTLAnalysisResult:
    """Result of IOCTL handler analysis."""

    ioctl_codes: list[IOCTLCode] = field(default_factory=list)
    handlers: list[DisassembledFunction] = field(default_factory=list)
    dangerous_patterns: list[tuple[str, int, str]] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)


class IOCTLDisassembler:
    """Disassemble and analyze IOCTL handlers in driver binaries."""

    def __init__(self, pe: pefile.PE, max_instructions: int = 500):
        self._pe = pe
        self._max_instructions = max_instructions
        self._image_base = pe.OPTIONAL_HEADER.ImageBase
        self._import_thunks: dict[int, str] = {}
        self._build_import_map()

        # Initialize Capstone for x64
        try:
            from capstone import CS_ARCH_X86, CS_MODE_64, Cs

            self._cs: Cs | None = Cs(CS_ARCH_X86, CS_MODE_64)
            if self._cs:
                self._cs.detail = True
        except ImportError:
            self._cs = None

    def _build_import_map(self) -> None:
        """Build a map of import thunk addresses to function names."""
        if not hasattr(self._pe, "DIRECTORY_ENTRY_IMPORT"):
            return

        for entry in self._pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode("utf-8", errors="ignore")
                    self._import_thunks[imp.address] = name

    def analyze(self) -> IOCTLAnalysisResult:
        """Perform full IOCTL analysis."""
        result = IOCTLAnalysisResult()

        # Find IOCTL codes in the binary
        result.ioctl_codes = self._find_ioctl_codes()

        # Find and disassemble IOCTL handlers
        handler_addresses = self._find_ioctl_handlers()
        for addr in handler_addresses:
            func = self._disassemble_function(addr)
            if func:
                result.handlers.append(func)
                result.dangerous_patterns.extend(
                    (pattern, addr, func.name) for addr, _, pattern in func.dangerous_instructions
                )

        # Scan all code for dangerous patterns
        self._scan_for_dangerous_patterns(result)

        # Assess vulnerabilities
        self._assess_vulnerabilities(result)

        return result

    def _find_ioctl_codes(self) -> list[IOCTLCode]:
        """Find IOCTL codes embedded in the driver."""
        codes: list[IOCTLCode] = []
        seen: set[int] = set()

        try:
            data = self._pe.get_memory_mapped_image()
        except Exception:
            return codes

        # Scan for 4-byte values that look like IOCTL codes
        # IOCTL codes typically have device type in range 0x0000-0xFFFF
        # and follow certain patterns
        for i in range(0, len(data) - 4, 4):
            val = struct.unpack("<I", data[i : i + 4])[0]

            # Skip if already seen or obviously not an IOCTL
            if val in seen or val in {0, 0xFFFFFFFF}:
                continue

            # Check if it looks like a valid IOCTL code
            device_type = (val >> 16) & 0xFFFF
            function = (val >> 2) & 0xFFF
            method = val & 0x3
            access = (val >> 14) & 0x3

            # Heuristics for valid IOCTL codes
            # - Device type should be reasonable (not random garbage)
            # - Function code should be non-zero and not too large
            if 0 < device_type <= 0xA000 and 0 < function < 0x800 and method <= 3 and access <= 3:
                # Additional check: common vulnerable driver device types
                is_interesting = (
                    device_type in DEVICE_TYPES
                    or device_type == 0x22  # FILE_DEVICE_UNKNOWN (very common)
                    or 0x9C00 <= device_type <= 0xA000  # Custom device types
                )

                if is_interesting:
                    codes.append(IOCTLCode.from_raw(val))
                    seen.add(val)

        return codes

    def _find_ioctl_handlers(self) -> list[int]:
        """Find potential IOCTL handler function addresses."""
        handlers: list[int] = []

        # Check exports for handler-like names
        if hasattr(self._pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in self._pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    name = exp.name.decode("utf-8", errors="ignore")
                    if any(h.lower() in name.lower() for h in IOCTL_HANDLER_NAMES):
                        handlers.append(exp.address)

        # Look for IRP_MJ_DEVICE_CONTROL dispatch routine setup
        # This is typically in DriverEntry: DriverObject->MajorFunction[14] = handler
        # Pattern: mov qword ptr [rcx+70h], <handler_addr>
        # (0x70 = 14 * 8 = offset for IRP_MJ_DEVICE_CONTROL in x64)

        try:
            data = self._pe.get_memory_mapped_image()
            # Pattern for mov [rcx+70h], rax (common setup pattern)
            patterns = [
                b"\x48\x89\x41\x70",  # mov [rcx+70h], rax
                b"\x48\x89\x81\x70\x00\x00\x00",  # mov [rcx+70h], rax (larger offset encoding)
            ]

            for pattern in patterns:
                offset = 0
                while True:
                    idx = data.find(pattern, offset)
                    if idx == -1:
                        break

                    # Try to find what was loaded into rax before this
                    # Look for lea rax, [rip+offset] pattern in the preceding bytes
                    context = data[max(0, idx - 20) : idx]
                    # This is a simplified heuristic
                    if b"\x48\x8d\x05" in context:  # lea rax, [rip+...]
                        lea_idx = context.rfind(b"\x48\x8d\x05")
                        if lea_idx >= 0 and lea_idx + 7 <= len(context):
                            rip_offset = struct.unpack("<i", context[lea_idx + 3 : lea_idx + 7])[0]
                            handler_rva = idx - 20 + lea_idx + 7 + rip_offset
                            handlers.append(self._image_base + handler_rva)

                    offset = idx + 1
        except Exception:
            pass

        return list(set(handlers))

    def _disassemble_function(
        self, address: int, name: str = "unknown"
    ) -> DisassembledFunction | None:
        """Disassemble a function at the given address."""
        if not self._cs:
            return None

        try:
            # Convert VA to file offset
            rva = address - self._image_base
            offset = self._pe.get_offset_from_rva(rva)
            data = self._pe.get_memory_mapped_image()

            if offset < 0 or offset >= len(data):
                return None

            func = DisassembledFunction(name=name, address=address, size=0)

            # Disassemble until we hit a return or max instructions
            code = data[offset : offset + self._max_instructions * 15]  # ~15 bytes max per x64 insn

            for insn in self._cs.disasm(code, address):
                insn_bytes = bytes(insn.bytes)
                func.instructions.append((insn.address, insn.mnemonic, insn.op_str, insn_bytes))
                func.size += insn.size

                # Check for dangerous patterns
                if insn_bytes[:2] in DANGEROUS_PATTERNS:
                    pattern_name = DANGEROUS_PATTERNS[insn_bytes[:2]]
                    func.dangerous_instructions.append((insn.address, insn.mnemonic, pattern_name))
                elif insn_bytes[:1] in [bytes([b]) for b in b"\xec\xed\xee\xef\xe4\xe5\xe6\xe7"]:
                    pattern_name = DANGEROUS_PATTERNS.get(insn_bytes[:1], "port_io")
                    func.dangerous_instructions.append((insn.address, insn.mnemonic, pattern_name))

                # Track call targets
                if insn.mnemonic == "call":
                    # Check if it's a call to an import
                    for op in insn.operands:
                        if op.type == 2:  # X86_OP_IMM
                            target = op.imm
                            if target in self._import_thunks:
                                func.called_imports.append(self._import_thunks[target])
                            else:
                                func.called_functions.append(target)

                # Stop at ret
                if insn.mnemonic == "ret":
                    break

                if len(func.instructions) >= self._max_instructions:
                    break

            return func

        except Exception:
            return None

    def _scan_for_dangerous_patterns(self, result: IOCTLAnalysisResult) -> None:
        """Scan entire code section for dangerous instruction patterns."""
        try:
            data = self._pe.get_memory_mapped_image()
        except Exception:
            return

        for pattern, name in DANGEROUS_PATTERNS.items():
            offset = 0
            while True:
                idx = data.find(pattern, offset)
                if idx == -1:
                    break

                # Convert to RVA
                try:
                    rva = idx
                    va = self._image_base + rva

                    # Check if this is in a code section
                    for section in self._pe.sections:
                        section_start = section.VirtualAddress
                        section_end = section_start + section.Misc_VirtualSize
                        if section_start <= rva < section_end:
                            # Check if executable
                            if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                                result.dangerous_patterns.append((name, va, "code_section"))
                            break
                except Exception:
                    pass

                offset = idx + 1

    def _assess_vulnerabilities(self, result: IOCTLAnalysisResult) -> None:
        """Assess potential vulnerabilities based on findings."""
        # Check for MSR access
        msr_patterns = [p for p, _, _ in result.dangerous_patterns if "msr" in p]
        if msr_patterns:
            result.vulnerabilities.append(
                f"MSR read/write detected ({len(msr_patterns)} locations) - "
                "can be used for arbitrary kernel code execution"
            )

        # Check for port I/O
        port_patterns = [
            p
            for p, _, _ in result.dangerous_patterns
            if "port" in p.lower() or p.startswith("in ") or p.startswith("out ")
        ]
        if port_patterns:
            result.vulnerabilities.append(
                f"Port I/O detected ({len(port_patterns)} locations) - "
                "can be used for hardware manipulation"
            )

        # Check for CR register access
        cr_patterns = [p for p, _, _ in result.dangerous_patterns if "cr" in p.lower()]
        if cr_patterns:
            result.vulnerabilities.append(
                f"Control register access detected ({len(cr_patterns)} locations) - "
                "can be used to disable security features"
            )

        # Check IOCTL codes for METHOD_NEITHER (most dangerous)
        neither_ioctls = [c for c in result.ioctl_codes if c.method == IOCTLMethod.NEITHER]
        if neither_ioctls:
            result.vulnerabilities.append(
                f"{len(neither_ioctls)} IOCTL(s) use METHOD_NEITHER - "
                "prone to double-fetch and arbitrary memory access bugs"
            )

        # Check for dangerous import calls in handlers
        dangerous_calls = set()
        for handler in result.handlers:
            for imp in handler.called_imports:
                if imp in [
                    "MmMapIoSpace",
                    "MmMapIoSpaceEx",
                    "__readmsr",
                    "__writemsr",
                    "MmMapLockedPages",
                    "MmMapLockedPagesSpecifyCache",
                    "ZwMapViewOfSection",
                ]:
                    dangerous_calls.add(imp)

        if dangerous_calls:
            result.vulnerabilities.append(
                f"IOCTL handler calls dangerous APIs: {', '.join(dangerous_calls)}"
            )


def analyze_driver_ioctls(pe: pefile.PE, max_instructions: int = 500) -> IOCTLAnalysisResult:
    """Convenience function to analyze a PE file for IOCTL vulnerabilities."""
    analyzer = IOCTLDisassembler(pe, max_instructions)
    return analyzer.analyze()
