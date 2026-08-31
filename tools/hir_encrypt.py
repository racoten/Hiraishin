#!/usr/bin/env python3
"""
hir_encrypt.py - Post-link encryption tool for Crystal Palace PICO blobs.

Adapted from the original Minato hiraishin_encrypt.py. Works on COFF object
files (.o) and raw PICO blobs instead of PE files.

Crystal Palace PICOs lack PE headers, so this tool:
  1. Parses the COFF object file to extract symbol/section information.
  2. Identifies functions by prefix (default: REG_) or explicit list.
  3. Applies rolling 4-byte XOR encryption to each function body.
  4. Optionally patches the PICO blob with the encrypted bytes.
  5. Produces a JSON manifest documenting all encrypted regions.

Two modes of operation:
  Object file mode  - encrypts functions directly in the .o file.
  PICO blob mode    - uses the .o for symbol info, encrypts in the blob.

Usage examples:
  # Encrypt functions in the object file (pre-link)
  python hir_encrypt.py --obj protected_funcs.x64.o

  # Encrypt functions in the PICO blob (post-link)
  python hir_encrypt.py --obj protected_funcs.x64.o --pico hiraishin.pico.bin

  # With explicit output and manifest paths
  python hir_encrypt.py --obj protected_funcs.x64.o --pico hiraishin.pico.bin \\
      --output encrypted.pico.bin --manifest manifest.json

  # Use a specific prefix filter
  python hir_encrypt.py --obj protected_funcs.x64.o --prefix PROTECTED_

  # Encrypt only specific functions
  python hir_encrypt.py --obj protected_funcs.x64.o --functions REG_Alloc,REG_Dispatch

  # Use a fixed key (for reproducible builds / testing)
  python hir_encrypt.py --obj protected_funcs.x64.o --key DEADBEEF

Requirements: Python 3.6+ standard library only.
"""

import argparse
import json
import math
import os
import secrets
import struct
import sys
from collections import OrderedDict
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Terminal colours (Windows-safe: enable VT100 if possible)
# ---------------------------------------------------------------------------

def _enable_vt100():
    """Try to enable VT100 escape sequences on Windows 10+."""
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass

_enable_vt100()

CLR_RESET  = "\033[0m"
CLR_RED    = "\033[91m"
CLR_GREEN  = "\033[92m"
CLR_YELLOW = "\033[93m"
CLR_CYAN   = "\033[96m"
CLR_BOLD   = "\033[1m"
CLR_DIM    = "\033[2m"

def info(msg):
    print(f"  {CLR_CYAN}[*]{CLR_RESET} {msg}")

def ok(msg):
    print(f"  {CLR_GREEN}[+]{CLR_RESET} {msg}")

def warn(msg):
    print(f"  {CLR_YELLOW}[!]{CLR_RESET} {msg}")

def err(msg):
    print(f"  {CLR_RED}[-]{CLR_RESET} {msg}", file=sys.stderr)

def banner():
    print(f"""
{CLR_BOLD}{CLR_CYAN}  ===================================================
   hir_encrypt  -  Crystal Palace PICO Encryption Tool
  ==================================================={CLR_RESET}
""")

# ---------------------------------------------------------------------------
# COFF constants
# ---------------------------------------------------------------------------

# Machine types
IMAGE_FILE_MACHINE_AMD64  = 0x8664
IMAGE_FILE_MACHINE_I386   = 0x014c
IMAGE_FILE_MACHINE_ARM64  = 0xAA64

MACHINE_NAMES = {
    IMAGE_FILE_MACHINE_AMD64: "x86-64",
    IMAGE_FILE_MACHINE_I386:  "i386",
    IMAGE_FILE_MACHINE_ARM64: "ARM64",
}

# Section flags
IMAGE_SCN_CNT_CODE             = 0x00000020
IMAGE_SCN_MEM_EXECUTE          = 0x20000000

# Symbol storage classes
IMAGE_SYM_CLASS_EXTERNAL       = 2
IMAGE_SYM_CLASS_STATIC         = 3
IMAGE_SYM_CLASS_LABEL          = 6

# Symbol section number specials
IMAGE_SYM_UNDEFINED = 0
IMAGE_SYM_ABSOLUTE  = 0xFFFF  # -1 as uint16
IMAGE_SYM_DEBUG     = 0xFFFE  # -2 as uint16

# Symbol type
IMAGE_SYM_DTYPE_FUNCTION = 0x20  # (2 << 4) -- function in complex type

# COFF header size: 20 bytes
COFF_HEADER_SIZE = 20
# Section header size: 40 bytes
SECTION_HEADER_SIZE = 40
# Symbol table entry size: 18 bytes
SYMBOL_ENTRY_SIZE = 18

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class CoffHeader:
    """Parsed COFF file header (20 bytes)."""
    __slots__ = (
        "machine", "num_sections", "timestamp",
        "symtab_offset", "num_symbols", "opt_header_size", "characteristics",
    )

    @classmethod
    def from_bytes(cls, data, offset=0):
        hdr = cls()
        (
            hdr.machine,
            hdr.num_sections,
            hdr.timestamp,
            hdr.symtab_offset,
            hdr.num_symbols,
            hdr.opt_header_size,
            hdr.characteristics,
        ) = struct.unpack_from("<HHIIIHH", data, offset)
        return hdr

    @property
    def is_64bit(self):
        return self.machine in (IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64)

    @property
    def machine_name(self):
        return MACHINE_NAMES.get(self.machine, f"0x{self.machine:04X}")


class SectionHeader:
    """Parsed COFF section header (40 bytes)."""
    __slots__ = (
        "name", "virtual_size", "virtual_address",
        "raw_data_size", "raw_data_offset", "reloc_offset", "linenum_offset",
        "num_relocs", "num_linenums", "characteristics",
    )

    @classmethod
    def from_bytes(cls, data, offset=0):
        sec = cls()
        name_bytes = data[offset:offset + 8]
        (
            sec.virtual_size,
            sec.virtual_address,
            sec.raw_data_size,
            sec.raw_data_offset,
            sec.reloc_offset,
            sec.linenum_offset,
            sec.num_relocs,
            sec.num_linenums,
            sec.characteristics,
        ) = struct.unpack_from("<IIIIIIHHI", data, offset + 8)

        # Name decoding: if starts with '/' it is a string table offset.
        # If the first 4 bytes are zero, bytes 4..7 are a uint32 offset
        # into the string table.
        if name_bytes[:4] == b"\x00\x00\x00\x00":
            sec.name = struct.unpack_from("<I", name_bytes, 4)[0]  # strtab offset
        else:
            sec.name = name_bytes.rstrip(b"\x00").decode("ascii", errors="replace")
        return sec

    @property
    def is_code(self):
        return bool(self.characteristics & IMAGE_SCN_CNT_CODE)

    @property
    def is_executable(self):
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)


class CoffSymbol:
    """Parsed COFF symbol table entry (18 bytes)."""
    __slots__ = (
        "name", "value", "section_number", "type_field",
        "storage_class", "num_aux",
    )

    @classmethod
    def from_bytes(cls, data, offset, string_table):
        sym = cls()
        name_bytes = data[offset:offset + 8]
        (
            sym.value,
            sym.section_number,
            sym.type_field,
            sym.storage_class,
            sym.num_aux,
        ) = struct.unpack_from("<IhHBB", data, offset + 8)

        # Name: if first 4 bytes are zero, bytes 4..7 give string table offset
        if name_bytes[:4] == b"\x00\x00\x00\x00":
            strtab_off = struct.unpack_from("<I", name_bytes, 4)[0]
            sym.name = _read_strtab(string_table, strtab_off)
        else:
            sym.name = name_bytes.rstrip(b"\x00").decode("ascii", errors="replace")
        return sym

    @property
    def is_function(self):
        return (self.type_field & 0xF0) == IMAGE_SYM_DTYPE_FUNCTION

    @property
    def is_external(self):
        return self.storage_class == IMAGE_SYM_CLASS_EXTERNAL

    @property
    def is_defined(self):
        return self.section_number > 0


def _read_strtab(strtab, offset):
    """Read a NUL-terminated string from the COFF string table."""
    if strtab is None or offset >= len(strtab):
        return "<unknown>"
    end = strtab.index(b"\x00", offset) if b"\x00" in strtab[offset:] else len(strtab)
    return strtab[offset:end].decode("ascii", errors="replace")


# ---------------------------------------------------------------------------
# COFF parser
# ---------------------------------------------------------------------------

class CoffFile:
    """Minimal COFF object file parser for symbol and section extraction."""

    def __init__(self, data):
        self.data = data
        self.header = None
        self.sections = []
        self.symbols = []
        self.string_table = None
        self._parse()

    def _parse(self):
        data = self.data

        # Detect whether there is a PE signature (skip if so)
        pe_offset = 0
        if len(data) >= 2 and data[:2] == b"MZ":
            # PE file -- skip to COFF header
            if len(data) >= 0x3C + 4:
                pe_sig_off = struct.unpack_from("<I", data, 0x3C)[0]
                if len(data) >= pe_sig_off + 4 and data[pe_sig_off:pe_sig_off + 4] == b"PE\x00\x00":
                    pe_offset = pe_sig_off + 4

        self.header = CoffHeader.from_bytes(data, pe_offset)
        hdr = self.header

        if hdr.machine not in MACHINE_NAMES:
            warn(f"Unknown machine type 0x{hdr.machine:04X}, proceeding anyway")

        # Parse section headers
        sec_offset = pe_offset + COFF_HEADER_SIZE + hdr.opt_header_size
        for i in range(hdr.num_sections):
            off = sec_offset + i * SECTION_HEADER_SIZE
            sec = SectionHeader.from_bytes(data, off)
            # Resolve section name from string table if needed
            if isinstance(sec.name, int):
                # Will resolve after string table is loaded
                pass
            self.sections.append(sec)

        # Load string table (immediately after symbol table)
        if hdr.symtab_offset > 0 and hdr.num_symbols > 0:
            strtab_off = hdr.symtab_offset + hdr.num_symbols * SYMBOL_ENTRY_SIZE
            if strtab_off + 4 <= len(data):
                strtab_size = struct.unpack_from("<I", data, strtab_off)[0]
                if strtab_size >= 4 and strtab_off + strtab_size <= len(data):
                    self.string_table = data[strtab_off:strtab_off + strtab_size]
                else:
                    self.string_table = data[strtab_off:]
            else:
                self.string_table = None
        else:
            self.string_table = None

        # Resolve section names that are string table references
        for sec in self.sections:
            if isinstance(sec.name, int) and self.string_table is not None:
                sec.name = _read_strtab(self.string_table, sec.name)

        # Parse symbol table
        if hdr.symtab_offset > 0 and hdr.num_symbols > 0:
            idx = 0
            while idx < hdr.num_symbols:
                off = hdr.symtab_offset + idx * SYMBOL_ENTRY_SIZE
                if off + SYMBOL_ENTRY_SIZE > len(data):
                    break
                sym = CoffSymbol.from_bytes(data, off, self.string_table)
                self.symbols.append(sym)
                # Skip auxiliary symbol records
                idx += 1 + sym.num_aux

    def get_code_sections(self):
        """Return (index_1based, SectionHeader) for code sections."""
        results = []
        for i, sec in enumerate(self.sections):
            if sec.is_code or sec.is_executable:
                results.append((i + 1, sec))  # COFF sections are 1-based
        return results

    def get_section_data(self, sec):
        """Return the raw bytes for a section."""
        if sec.raw_data_offset == 0 or sec.raw_data_size == 0:
            return b""
        return self.data[sec.raw_data_offset:sec.raw_data_offset + sec.raw_data_size]

    def get_functions(self, prefix=None, explicit_names=None):
        """
        Return a list of (name, section_index_1based, offset_in_section, size)
        for functions matching the filter criteria.

        Size is estimated from the gap to the next symbol in the same section,
        or from .pdata if available.
        """
        # Gather all defined function symbols, sorted by (section, value)
        func_syms = []
        for sym in self.symbols:
            if not sym.is_defined:
                continue
            if sym.section_number <= 0:
                continue
            # Accept if it is typed as function OR is external AND matches prefix
            is_func = sym.is_function
            name_match = False
            if prefix and sym.name.startswith(prefix):
                name_match = True
            if explicit_names and sym.name in explicit_names:
                name_match = True
            if prefix is None and explicit_names is None:
                # No filter -- take all functions
                if is_func and sym.is_external:
                    name_match = True

            if name_match or (is_func and (name_match or (prefix is None and explicit_names is None))):
                func_syms.append(sym)

        # De-duplicate by name
        seen = set()
        unique = []
        for sym in func_syms:
            if sym.name not in seen:
                seen.add(sym.name)
                unique.append(sym)
        func_syms = unique

        # Build sorted list of unique symbol offsets per section for
        # gap-based size computation. Only include symbols with
        # non-zero type (functions) or external storage class to
        # avoid section-name symbols (.text, .data) polluting the list.
        sec_offsets = {}
        for sym in self.symbols:
            if sym.is_defined and sym.section_number > 0:
                if sym.is_function or sym.is_external or sym.storage_class == IMAGE_SYM_CLASS_LABEL:
                    sec_offsets.setdefault(sym.section_number, set()).add(sym.value)

        # Also add all func_syms offsets to ensure they're present
        for sym in func_syms:
            sec_offsets.setdefault(sym.section_number, set()).add(sym.value)

        # Sort offsets per section
        sec_sorted = {k: sorted(v) for k, v in sec_offsets.items()}

        # Compute sizes
        results = []
        for sym in func_syms:
            sec_num = sym.section_number
            sec_idx = sec_num - 1
            if sec_idx < 0 or sec_idx >= len(self.sections):
                continue
            sec = self.sections[sec_idx]

            offsets = sec_sorted.get(sec_num, [])
            size = 0
            for i, off in enumerate(offsets):
                if off == sym.value:
                    if i + 1 < len(offsets):
                        size = offsets[i + 1] - sym.value
                    else:
                        size = sec.raw_data_size - sym.value
                    break

            if size <= 0:
                size = sec.raw_data_size - sym.value
                if size <= 0:
                    warn(f"Cannot determine size for {sym.name}, skipping")
                    continue

            results.append((sym.name, sec_num, sym.value, size))

        # Filter by prefix / explicit names
        if prefix:
            results = [(n, s, o, sz) for n, s, o, sz in results if n.startswith(prefix)]
        if explicit_names:
            results = [(n, s, o, sz) for n, s, o, sz in results if n in explicit_names]

        return results


# ---------------------------------------------------------------------------
# Encryption primitives
# ---------------------------------------------------------------------------

def generate_xor_key(length=4):
    """Generate a cryptographically random XOR key."""
    return secrets.token_bytes(length)


def parse_hex_key(hex_str):
    """Parse a hex string into raw XOR key bytes.

    Bytes are used in the order given: 'DEADBEEF' -> b'\\xde\\xad\\xbe\\xef'.
    This matches generate_xor_key() output and manifest key_hex values.

    NOTE on C interop: C workmask_xor decomposes a uint32_t key in
    little-endian byte order, so C constant 0xDEADBEEF produces XOR
    bytes [EF, BE, AD, DE]. To match that from the command line, pass
    the bytes in memory order: --key EFBEADDE (not DEADBEEF).
    """
    hex_str = hex_str.strip().replace("0x", "").replace("0X", "")
    if len(hex_str) % 2 != 0:
        hex_str = "0" + hex_str
    return bytes.fromhex(hex_str)


def xor_encrypt(data, key):
    """
    Rolling XOR encryption matching workmask_xor() in workmask.c.

    Applies a repeating key over the data buffer:
        encrypted[i] = data[i] ^ key[i % key_len]

    This is symmetric: encrypting twice with the same key recovers
    the original data.
    """
    key_len = len(key)
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % key_len]
    return bytes(result)


def shannon_entropy(data):
    """Calculate Shannon entropy of a byte sequence (0.0 - 8.0)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# Common x86-64 function prologue patterns
# ---------------------------------------------------------------------------

X86_PROLOGUES = [
    b"\x48\x89\x5c\x24",    # mov [rsp+...], rbx
    b"\x48\x83\xec",        # sub rsp, imm8
    b"\x48\x81\xec",        # sub rsp, imm32
    b"\x55",                # push rbp
    b"\x40\x55",            # rex push rbp
    b"\x48\x8b\xec",        # mov rbp, rsp
    b"\x40\x53",            # rex push rbx
    b"\x56",                # push rsi
    b"\x57",                # push rdi
    b"\x41\x54",            # push r12
    b"\x41\x55",            # push r13
    b"\x41\x56",            # push r14
    b"\x41\x57",            # push r15
    b"\x4c\x8b\xdc",        # mov r11, rsp
    b"\x48\x89\x4c\x24",    # mov [rsp+...], rcx
]


def has_prologue(data):
    """Check if data starts with a common x86-64 prologue pattern."""
    for pat in X86_PROLOGUES:
        if data[:len(pat)] == pat:
            return True
    return False


# ---------------------------------------------------------------------------
# Encryption engine
# ---------------------------------------------------------------------------

class EncryptionResult:
    """Result of encrypting a single function."""
    __slots__ = (
        "name", "section_index", "offset_in_section",
        "offset_in_blob", "size", "key",
        "entropy_before", "entropy_after",
        "had_prologue", "has_prologue_after",
    )

    def to_dict(self):
        return OrderedDict([
            ("name", self.name),
            ("section_index", self.section_index),
            ("offset_in_section", self.offset_in_section),
            ("offset_in_blob", self.offset_in_blob),
            ("size", self.size),
            ("key_hex", self.key.hex()),
            ("entropy_before", round(self.entropy_before, 4)),
            ("entropy_after", round(self.entropy_after, 4)),
            ("had_prologue", self.had_prologue),
            ("has_prologue_after", self.has_prologue_after),
        ])


def encrypt_functions(coff, target_data, target_base_offset,
                      functions, fixed_key=None):
    """
    Encrypt function bodies in *target_data* (a mutable bytearray).

    Parameters:
        coff             - CoffFile for symbol/section info
        target_data      - bytearray to patch (object file or PICO blob)
        target_base_offset - offset within target_data where .text starts
                             (for object file: section.raw_data_offset;
                              for PICO blob: 0 or user-specified)
        functions        - list of (name, sec_num, offset_in_section, size)
        fixed_key        - if set, use this key for all functions

    Returns a list of EncryptionResult.
    """
    results = []

    for name, sec_num, sec_offset, size in functions:
        # Compute absolute offset in the target buffer
        abs_offset = target_base_offset + sec_offset

        if abs_offset + size > len(target_data):
            warn(f"Function {name} at offset 0x{abs_offset:X} + 0x{size:X} "
                 f"exceeds target size 0x{len(target_data):X}, skipping")
            continue

        if size < 1:
            warn(f"Function {name} has zero size, skipping")
            continue

        # Extract original bytes
        original = bytes(target_data[abs_offset:abs_offset + size])

        # Generate or use fixed key
        key = fixed_key if fixed_key else generate_xor_key(4)

        # Compute pre-encryption metrics
        entropy_before = shannon_entropy(original)
        prologue_before = has_prologue(original)

        # Encrypt
        encrypted = xor_encrypt(original, key)

        # Compute post-encryption metrics
        entropy_after = shannon_entropy(encrypted)
        prologue_after = has_prologue(encrypted)

        # Patch in place
        target_data[abs_offset:abs_offset + size] = encrypted

        # Record result
        r = EncryptionResult()
        r.name = name
        r.section_index = sec_num
        r.offset_in_section = sec_offset
        r.offset_in_blob = abs_offset
        r.size = size
        r.key = key
        r.entropy_before = entropy_before
        r.entropy_after = entropy_after
        r.had_prologue = prologue_before
        r.has_prologue_after = prologue_after
        results.append(r)

    return results


# ---------------------------------------------------------------------------
# Manifest generation
# ---------------------------------------------------------------------------

def build_manifest(coff, results, obj_path, pico_path, mode):
    """Build the JSON manifest documenting encryption results."""
    manifest = OrderedDict()
    manifest["tool"] = "hir_encrypt"
    manifest["version"] = "1.0.0"
    manifest["timestamp"] = datetime.now(timezone.utc).isoformat()
    manifest["mode"] = mode
    manifest["object_file"] = os.path.basename(obj_path)
    if pico_path:
        manifest["pico_file"] = os.path.basename(pico_path)
    manifest["machine"] = coff.header.machine_name
    manifest["is_64bit"] = coff.header.is_64bit
    manifest["total_functions_encrypted"] = len(results)
    manifest["total_bytes_encrypted"] = sum(r.size for r in results)

    entries = []
    for r in results:
        entries.append(r.to_dict())
    manifest["functions"] = entries

    # Summary statistics
    if results:
        entropies_before = [r.entropy_before for r in results]
        entropies_after  = [r.entropy_after for r in results]
        manifest["entropy_summary"] = OrderedDict([
            ("avg_before", round(sum(entropies_before) / len(entropies_before), 4)),
            ("avg_after",  round(sum(entropies_after) / len(entropies_after), 4)),
            ("min_after",  round(min(entropies_after), 4)),
            ("max_after",  round(max(entropies_after), 4)),
        ])

    return manifest


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Crystal Palace PICO post-link encryption tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt in object file (pre-link)
  python hir_encrypt.py --obj protected_funcs.x64.o

  # Encrypt in PICO blob (post-link)
  python hir_encrypt.py --obj protected_funcs.x64.o --pico hiraishin.pico.bin

  # Fixed key for reproducible testing
  python hir_encrypt.py --obj protected_funcs.x64.o --key DEADBEEF

  # Encrypt only specific functions
  python hir_encrypt.py --obj protected_funcs.x64.o --functions REG_Alloc,REG_Free
""",
    )
    parser.add_argument("--obj", required=True,
                        help="COFF object file (.o) for symbol/section info")
    parser.add_argument("--pico",
                        help="PICO blob to encrypt (post-link mode)")
    parser.add_argument("--output", "-o",
                        help="Output file path (default: overwrite input or <name>.enc.<ext>)")
    parser.add_argument("--manifest", "-m",
                        help="JSON manifest output path (default: <output>.manifest.json)")
    parser.add_argument("--prefix", default="REG_",
                        help="Function name prefix to match (default: REG_)")
    parser.add_argument("--functions",
                        help="Comma-separated list of specific function names to encrypt")
    parser.add_argument("--key",
                        help="Fixed hex XOR key (e.g. DEADBEEF). Random if omitted.")
    parser.add_argument("--blob-offset", type=lambda x: int(x, 0), default=0,
                        help="Offset within PICO blob where .text content begins (default: 0)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Analyse but do not write any files")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress informational output")

    args = parser.parse_args()

    if not args.quiet:
        banner()

    # ---- Load object file ----
    if not os.path.isfile(args.obj):
        err(f"Object file not found: {args.obj}")
        return 1

    with open(args.obj, "rb") as f:
        obj_data = f.read()

    if not args.quiet:
        info(f"Loaded object file: {args.obj} ({len(obj_data)} bytes)")

    coff = CoffFile(obj_data)
    if not args.quiet:
        info(f"Machine: {coff.header.machine_name}  "
             f"Sections: {coff.header.num_sections}  "
             f"Symbols: {coff.header.num_symbols}")

    # ---- Find code sections ----
    code_sections = coff.get_code_sections()
    if not code_sections:
        err("No code sections found in the object file.")
        return 1

    if not args.quiet:
        for sec_num, sec in code_sections:
            info(f"Code section [{sec_num}] '{sec.name}': "
                 f"offset=0x{sec.raw_data_offset:X}, size=0x{sec.raw_data_size:X}")

    # ---- Find target functions ----
    explicit_names = None
    if args.functions:
        explicit_names = set(args.functions.split(","))

    functions = coff.get_functions(
        prefix=args.prefix if not explicit_names else None,
        explicit_names=explicit_names,
    )

    if not functions:
        err(f"No functions found matching prefix '{args.prefix}' "
            f"or names {explicit_names}")
        return 1

    if not args.quiet:
        info(f"Found {len(functions)} function(s) to encrypt:")
        for name, sec_num, offset, size in functions:
            print(f"       {CLR_BOLD}{name}{CLR_RESET}  "
                  f"sec={sec_num} offset=0x{offset:X} size=0x{size:X} ({size} bytes)")

    # ---- Determine mode and prepare target data ----
    fixed_key = None
    if args.key:
        fixed_key = parse_hex_key(args.key)
        if not args.quiet:
            info(f"Using fixed XOR key: {fixed_key.hex().upper()}")

    if args.pico:
        # PICO blob mode
        mode = "pico_blob"
        if not os.path.isfile(args.pico):
            err(f"PICO blob not found: {args.pico}")
            return 1
        with open(args.pico, "rb") as f:
            target_data = bytearray(f.read())
        if not args.quiet:
            info(f"Loaded PICO blob: {args.pico} ({len(target_data)} bytes)")
        base_offset = args.blob_offset
        output_path = args.output or _default_output(args.pico, ".enc")
    else:
        # Object file mode
        mode = "object_file"
        target_data = bytearray(obj_data)
        # Base offset is the raw data offset of the first code section
        base_offset = code_sections[0][1].raw_data_offset
        output_path = args.output or _default_output(args.obj, ".enc")

    if not args.quiet:
        info(f"Mode: {CLR_BOLD}{mode}{CLR_RESET}")
        info(f"Base offset for encryption: 0x{base_offset:X}")

    # ---- Patch HIRMETA_ENTRY metadata in the binary ----
    # The DECLARE_WORKMASK_META macro creates entries with funcSize=0xDEADBEEF
    # (sentinel) and codeOffset=0. We must patch these with real values so
    # the runtime can locate and decrypt function bodies.
    meta_patch_count = 0
    for name, sec_num, sec_offset, size in functions:
        meta_sym_name = "g_meta_" + name.replace("REG_", "", 1) if name.startswith("REG_") else "g_meta_" + name
        # Find the g_meta_* symbol in the COFF symbol table
        meta_sym = None
        for sym in coff.symbols:
            if sym.name == meta_sym_name and sym.is_defined and sym.section_number > 0:
                meta_sym = sym
                break
        if not meta_sym:
            warn(f"No metadata symbol '{meta_sym_name}' found for {name}")
            continue

        meta_sec_idx = meta_sym.section_number - 1
        if meta_sec_idx < 0 or meta_sec_idx >= len(coff.sections):
            warn(f"Metadata symbol '{meta_sym_name}' has invalid section index")
            continue
        meta_sec = coff.sections[meta_sec_idx]

        # HIRMETA_ENTRY layout (32 bytes):
        #   +0x00: int32_t  codeOffset
        #   +0x04: uint32_t funcSize     (0xDEADBEEF = unpatched)
        #   +0x08: uint32_t xorKey
        #   +0x0C: uint32_t prologueSkip
        #   +0x10: int32_t  refCount
        #   +0x14: uint32_t flags
        #   +0x18: uint8_t  reserved[8]
        meta_file_offset = meta_sec.raw_data_offset + meta_sym.value

        if mode == "object_file":
            patch_target = target_data
        else:
            # In PICO blob mode, metadata is in data portion. For now,
            # patch the object file copy and warn about PICO patching.
            patch_target = target_data
            warn(f"PICO blob metadata patching for '{meta_sym_name}' requires "
                 "Crystal Palace data-region offset knowledge. "
                 "Patching in object file copy instead.")

        if meta_file_offset + 32 > len(patch_target):
            warn(f"Metadata entry for {name} at offset 0x{meta_file_offset:X} "
                 f"exceeds file bounds")
            continue

        # Read current funcSize to verify it's the sentinel
        current_funcSize = struct.unpack_from('<I', patch_target, meta_file_offset + 4)[0]

        # Patch codeOffset: signed offset from code region base to function body
        # In object file mode, this is the function's offset within .text
        struct.pack_into('<i', patch_target, meta_file_offset + 0, sec_offset)

        # Patch funcSize
        struct.pack_into('<I', patch_target, meta_file_offset + 4, size)

        # If using a per-function random key, also patch xorKey so it
        # matches what we encrypt with
        if not fixed_key:
            new_key = generate_xor_key(4)
            key_u32 = struct.unpack('<I', new_key)[0]
            struct.pack_into('<I', patch_target, meta_file_offset + 8, key_u32)
            # Store the key for this function to use in encryption
            for i, (fn, _, _, _) in enumerate(functions):
                if fn == name:
                    functions[i] = (name, sec_num, sec_offset, size)
                    break
            # We'll use this key when encrypting below
            if not hasattr(main, '_per_func_keys'):
                main._per_func_keys = {}
            main._per_func_keys[name] = new_key

        meta_patch_count += 1
        if not args.quiet:
            sentinel_str = f" (was 0x{current_funcSize:08X})" if current_funcSize == 0xDEADBEEF else ""
            ok(f"Patched metadata: {meta_sym_name} -> "
               f"codeOffset=0x{sec_offset:X}, funcSize={size}{sentinel_str}")

    if not args.quiet:
        info(f"Patched {meta_patch_count}/{len(functions)} metadata entries")

    # ---- Encrypt ----
    # For per-function keys that were patched into metadata, use them
    per_func_keys = getattr(main, '_per_func_keys', {})

    def encrypt_with_per_func_keys(coff, target_data, base_offset, functions, fixed_key):
        """Wrapper that uses per-function keys when available."""
        results = []
        for name, sec_num, sec_offset, size in functions:
            key = fixed_key
            if not key and name in per_func_keys:
                key = per_func_keys[name]
            elif not key:
                key = generate_xor_key(4)

            abs_offset = base_offset + sec_offset
            if abs_offset + size > len(target_data):
                warn(f"Function {name} at offset 0x{abs_offset:X} + 0x{size:X} "
                     f"exceeds target size 0x{len(target_data):X}, skipping")
                continue
            if size < 1:
                warn(f"Function {name} has zero size, skipping")
                continue

            original = bytes(target_data[abs_offset:abs_offset + size])
            entropy_before = shannon_entropy(original)
            prologue_before = has_prologue(original)
            encrypted = xor_encrypt(original, key)
            entropy_after = shannon_entropy(encrypted)
            prologue_after = has_prologue(encrypted)

            target_data[abs_offset:abs_offset + size] = encrypted

            r = EncryptionResult()
            r.name = name
            r.section_index = sec_num
            r.offset_in_section = sec_offset
            r.offset_in_blob = abs_offset
            r.size = size
            r.key = key
            r.entropy_before = entropy_before
            r.entropy_after = entropy_after
            r.had_prologue = prologue_before
            r.has_prologue_after = prologue_after
            results.append(r)

            # Also patch the xorKey in metadata if we're in object mode
            if mode == "object_file" and name in per_func_keys:
                meta_sym_name = "g_meta_" + name.replace("REG_", "", 1) if name.startswith("REG_") else "g_meta_" + name
                for sym in coff.symbols:
                    if sym.name == meta_sym_name and sym.is_defined:
                        meta_sec = coff.sections[sym.section_number - 1]
                        moff = meta_sec.raw_data_offset + sym.value + 8
                        key_u32 = struct.unpack('<I', key)[0]
                        struct.pack_into('<I', target_data, moff, key_u32)
                        break

        return results

    results = encrypt_with_per_func_keys(
        coff, target_data, base_offset, functions, fixed_key,
    )

    if not results:
        err("No functions were encrypted.")
        return 1

    # ---- Report ----
    if not args.quiet:
        print()
        ok(f"Encrypted {len(results)} function(s):")
        total_bytes = 0
        for r in results:
            delta = r.entropy_after - r.entropy_before
            delta_str = f"+{delta:.2f}" if delta >= 0 else f"{delta:.2f}"
            status = CLR_GREEN + "GOOD" if r.entropy_after > 6.0 else CLR_YELLOW + "LOW "
            print(f"       {status}{CLR_RESET}  {CLR_BOLD}{r.name}{CLR_RESET}  "
                  f"size={r.size}  key={r.key.hex().upper()}  "
                  f"entropy {r.entropy_before:.2f} -> {r.entropy_after:.2f} ({delta_str})")
            total_bytes += r.size
        print()
        info(f"Total encrypted bytes: {total_bytes}")

    # ---- Write output ----
    if args.dry_run:
        if not args.quiet:
            warn("Dry run -- no files written.")
    else:
        with open(output_path, "wb") as f:
            f.write(target_data)
        if not args.quiet:
            ok(f"Written: {output_path}")

        # Write manifest
        manifest = build_manifest(coff, results, args.obj, args.pico, mode)
        manifest_path = args.manifest or (output_path + ".manifest.json")
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
        if not args.quiet:
            ok(f"Manifest: {manifest_path}")

    if not args.quiet:
        print()

    return 0


def _default_output(path, suffix):
    """Generate a default output path by inserting suffix before extension."""
    base, ext = os.path.splitext(path)
    return f"{base}{suffix}{ext}"


if __name__ == "__main__":
    sys.exit(main())
