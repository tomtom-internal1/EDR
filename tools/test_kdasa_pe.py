from __future__ import annotations

import importlib.util
import struct
import tempfile
from pathlib import Path


SPEC = importlib.util.spec_from_file_location("kdasa_pe", Path(__file__).with_name("kdasa_pe.py"))
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def build_minimal_pe() -> bytes:
    data = bytearray(0x400)

    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"

    coff = 0x84
    struct.pack_into("<H", data, coff + 0, 0x8664)  # x64
    struct.pack_into("<H", data, coff + 2, 1)       # one section
    struct.pack_into("<I", data, coff + 4, 0x12345678)
    struct.pack_into("<H", data, coff + 16, 0xF0)
    struct.pack_into("<H", data, coff + 18, 0x2022)

    opt = coff + 20
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<Q", data, opt + 0x18, 0x180000000)
    struct.pack_into("<I", data, opt + 0x38, 0x3000)
    struct.pack_into("<I", data, opt + 0x6C, 16)
    struct.pack_into("<H", data, opt + 0x46, 0x4140)  # ASLR + NX + CFG
    struct.pack_into("<II", data, opt + 0x70 + 8 * 4, 0x200, 0x40)

    sec = opt + 0xF0
    data[sec:sec + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", data, sec + 8, 0x100)
    struct.pack_into("<I", data, sec + 12, 0x1000)
    struct.pack_into("<I", data, sec + 16, 0x200)
    struct.pack_into("<I", data, sec + 20, 0x200)
    struct.pack_into("<I", data, sec + 36, 0x60000020)  # RX

    return bytes(data)


def test_parse_minimal_pe() -> None:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "sample.sys"
        path.write_bytes(build_minimal_pe())
        result = MODULE.parse_pe(path)

    assert result["machine"] == "x64"
    assert result["peKind"] == "PE32+"
    assert result["sectionCount"] == 1
    assert result["mitigations"]["dynamicBase_ASLR"] is True
    assert result["mitigations"]["nxCompat_DEP"] is True
    assert result["mitigations"]["guardCF"] is True
    assert result["hasSecurityDirectory"] is True
    assert result["writableExecutableSections"] == []
