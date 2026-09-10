"""Bounded ELF64 header reader, also copied verbatim into the isolated Worker image."""

from __future__ import annotations

import struct
from hashlib import sha256

MAX_ARTIFACT_BYTES = 256 * 1024
SCHEMA = "pajin.application.elf-header.v1"


def parse_header(content: bytes) -> dict[str, object]:
    """Read structural header fields only; never load or execute the input artifact."""
    if not 64 <= len(content) <= MAX_ARTIFACT_BYTES:
        raise ValueError("ELF artifact byte count is unsupported")
    ident = content[:16]
    if ident[:7] != b"\x7fELF\x02\x01\x01" or ident[9:] != bytes(7):
        raise ValueError("ELF identity is unsupported")
    (
        kind,
        machine,
        version,
        entry,
        phoff,
        shoff,
        flags,
        ehsize,
        phsize,
        phnum,
        shsize,
        shnum,
        shstrndx,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", content, 16)
    if kind not in (1, 2, 3) or machine not in (62, 183) or version != 1 or ehsize != 64:
        raise ValueError("ELF header type, machine or version is unsupported")
    if phnum == 65535 or shstrndx == 65535 or (shoff != 0 and shnum == 0):
        raise ValueError("ELF extended numbering is unsupported")
    for offset, size, count, expected in ((phoff, phsize, phnum, 56), (shoff, shsize, shnum, 64)):
        if count:
            if size != expected or offset < 64 or offset + count * size > len(content):
                raise ValueError("ELF header table is outside the artifact")
        elif offset != 0 or size not in (0, expected):
            raise ValueError("ELF empty header table is inconsistent")
    if (shnum == 0 and shstrndx != 0) or (shnum and shstrndx >= shnum):
        raise ValueError("ELF section-name index is outside the table")
    return {
        "schema": SCHEMA,
        "artifactSha256": sha256(content).hexdigest(),
        "artifactBytes": len(content),
        "class": 64,
        "byteOrder": "little",
        "osAbi": ident[7],
        "abiVersion": ident[8],
        "type": {1: "relocatable", 2: "executable", 3: "shared-object"}[kind],
        "machine": {62: "x86-64", 183: "aarch64"}[machine],
        "entryPoint": f"0x{entry:016x}",
        "flags": f"0x{flags:08x}",
        "programHeaderCount": phnum,
        "sectionHeaderCount": shnum,
        "sectionNameIndex": shstrndx,
    }
