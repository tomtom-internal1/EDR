#!/usr/bin/env python3
"""Offline PE/driver security-property extractor.

Reads a PE file as bytes and reports structural metadata only. It never loads
the image, executes it, or opens a driver device interface.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path


IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

MACHINE_NAMES = {
    0x014C: "x86",
    0x8664: "x64",
    0xAA64: "arm64",
    0x01C4: "arm",
}


class PEFormatError(ValueError):
    pass


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def read_c_string(data: bytes) -> str:
    return data.split(b"\x00", 1)[0].decode("ascii", errors="replace")


def parse_pe(path: Path) -> dict:
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEFormatError("missing DOS MZ header")

    pe_offset = u32(data, 0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise PEFormatError("missing PE signature")

    coff = pe_offset + 4
    machine = u16(data, coff)
    section_count = u16(data, coff + 2)
    timestamp = u32(data, coff + 4)
    optional_size = u16(data, coff + 16)
    characteristics = u16(data, coff + 18)

    opt = coff + 20
    if opt + optional_size > len(data):
        raise PEFormatError("truncated optional header")

    magic = u16(data, opt)
    if magic == 0x10B:
        pe_kind = "PE32"
        dll_offset = opt + 0x46
        image_base = u32(data, opt + 0x1C)
        size_of_image = u32(data, opt + 0x38)
        data_dir_count = u32(data, opt + 0x5C)
        data_dir = opt + 0x60
    elif magic == 0x20B:
        pe_kind = "PE32+"
        dll_offset = opt + 0x46
        image_base = struct.unpack_from("<Q", data, opt + 0x18)[0]
        size_of_image = u32(data, opt + 0x38)
        data_dir_count = u32(data, opt + 0x6C)
        data_dir = opt + 0x70
    else:
        raise PEFormatError(f"unsupported optional-header magic 0x{magic:04x}")

    dll_characteristics = u16(data, dll_offset)

    security_rva = 0
    security_size = 0
    if data_dir_count > 4 and data_dir + 8 * 5 <= len(data):
        # IMAGE_DIRECTORY_ENTRY_SECURITY is index 4.
        security_rva = u32(data, data_dir + 8 * 4)
        security_size = u32(data, data_dir + 8 * 4 + 4)

    sections = []
    section_off = opt + optional_size
    for index in range(section_count):
        off = section_off + index * 40
        if off + 40 > len(data):
            raise PEFormatError("truncated section table")

        raw_name = data[off:off + 8]
        name = read_c_string(raw_name)
        virtual_size = u32(data, off + 8)
        virtual_address = u32(data, off + 12)
        raw_size = u32(data, off + 16)
        raw_pointer = u32(data, off + 20)
        sec_chars = u32(data, off + 36)

        sections.append({
            "name": name,
            "virtualSize": virtual_size,
            "virtualAddress": f"0x{virtual_address:X}",
            "rawSize": raw_size,
            "rawPointer": raw_pointer,
            "executable": bool(sec_chars & IMAGE_SCN_MEM_EXECUTE),
            "readable": bool(sec_chars & IMAGE_SCN_MEM_READ),
            "writable": bool(sec_chars & IMAGE_SCN_MEM_WRITE),
            "characteristics": f"0x{sec_chars:08X}",
        })

    wx_sections = [
        s["name"] for s in sections
        if s["executable"] and s["writable"]
    ]

    return {
        "path": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "machine": MACHINE_NAMES.get(machine, f"unknown(0x{machine:04X})"),
        "peKind": pe_kind,
        "sectionCount": section_count,
        "timeDateStamp": timestamp,
        "sizeOfImage": size_of_image,
        "imageBase": f"0x{image_base:X}",
        "hasSecurityDirectory": bool(security_rva and security_size),
        "securityDirectoryFileOffsetOrVirtual": f"0x{security_rva:X}",
        "securityDirectorySize": security_size,
        "mitigations": {
            "dynamicBase_ASLR": bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE),
            "nxCompat_DEP": bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT),
            "highEntropyVA": bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA),
            "guardCF": bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF),
        },
        "writableExecutableSections": wx_sections,
        "sections": sections,
        "reviewFlags": [
            "writable-executable-section"
            for _ in wx_sections[:1]
        ] + [
            "missing-dynamic-base" if not (dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) else "",
            "missing-nx-compat" if not (dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) else "",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    result = parse_pe(args.pe)
    rendered = json.dumps(result, indent=2, ensure_ascii=False)

    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
