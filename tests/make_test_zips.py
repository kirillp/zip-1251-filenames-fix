# -*- coding: utf-8 -*-
"""Create test fixtures for zip-cp1251-to-utf8.mjs in this directory."""
import os
import shutil
import struct
import zlib
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def deflate(data):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def build(entries, comment=b""):
    """entries: dicts with name(bytes), data(bytes), method(0/8),
    flags(int), descriptor(None|'sig'|'nosig'), is_dir(bool)"""
    out = bytearray()
    central = []
    for e in entries:
        raw = e["data"]
        crc = zlib.crc32(raw) & 0xFFFFFFFF
        if e["method"] == 8:
            comp = deflate(raw)
        else:
            comp = raw
        flags = e["flags"]
        dd = e.get("descriptor")
        if dd:
            flags |= 0x08
        offset = len(out)
        l_csize = 0 if dd else len(comp)
        l_usize = 0 if dd else len(raw)
        out += struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 20, flags, e["method"], 0x6000, 0x5A21,
            crc, l_csize, l_usize, len(e["name"]), 0)
        out += e["name"]
        out += comp
        if dd == "sig":
            out += struct.pack("<IIII", 0x08074B50, crc, len(comp), len(raw))
        elif dd == "nosig":
            out += struct.pack("<III", crc, len(comp), len(raw))
        central.append(dict(e, crc=crc, csize=len(comp), usize=len(raw),
                            flags=flags, offset=offset))

    cd_off = len(out)
    for e in central:
        out += struct.pack(
            "<IHHHHHHIIIHHHHHII", 0x02014B50, 0x0014, 20, e["flags"], e["method"],
            0x6000, 0x5A21, e["crc"], e["csize"], e["usize"], len(e["name"]), 0, 0,
            0, 0, 0x10 if e.get("is_dir") else 0x20, e["offset"])
        out += e["name"]
    cd_size = len(out) - cd_off
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(central), len(central),
                       cd_size, cd_off, len(comment))
    out += comment
    return bytes(out)


def w(path, data):
    with open(os.path.join(HERE, path), "wb") as f:
        f.write(data)
    print("wrote", path, len(data), "bytes")


def russian(s):
    return s.encode("cp1251")


# 1) plain CP1251 archive (reuse the one built earlier in the repo root)
shutil.copyfile(os.path.join(ROOT, "russian-cp1251.zip"),
                os.path.join(HERE, "cp1251-plain.zip"))
print("wrote cp1251-plain.zip (copy)")

# 2) CP1251 archive with data descriptors (with and without signature)
w("cp1251-descriptors.zip", build([
    dict(name=russian("Папка/"), data=b"", method=0, flags=0, is_dir=True),
    dict(name=russian("Папка/С дескриптором и подписью.txt"),
         data="Сжатые данные с дескриптором (подпись есть).\n".encode("utf-8"),
         method=8, flags=0, descriptor="sig"),
    dict(name=russian("Без подписи.dat"),
         data="Данные без подписи дескриптора.\n".encode("utf-8"),
         method=0, flags=0, descriptor="nosig"),
    dict(name=russian("Обычный файл.txt"),
         data="Обычная запись без дескриптора.\n".encode("utf-8"),
         method=8, flags=0),
], comment=b"legacy archive"))

# 3) mixed archive: one already-UTF-8 entry + one CP1251 entry
w("mixed.zip", build([
    dict(name="Уже UTF-8.txt".encode("utf-8"),
         data=b"already utf-8 flagged\n", method=8, flags=0x800),
    dict(name=russian("Ещё CP1251.txt"),
         data=b"still cp1251\n", method=8, flags=0),
]))

# 4) already UTF-8 archive written by a modern tool
p = os.path.join(HERE, "utf8-names.zip")
with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("Современный архив/файл.txt", "сделано современным инструментом\n")
    zf.writestr("Второй файл.txt", "второй\n")
print("wrote utf8-names.zip")

# 5) ASCII-only names without the UTF-8 flag
p = os.path.join(HERE, "ascii-names.zip")
with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
    zi = zipfile.ZipInfo("plain-ascii.txt")
    zi.flag_bits &= ~0x800
    zf.writestr(zi, "ascii name, no utf-8 flag\n")
print("wrote ascii-names.zip")

# 6) ZIP64 entry (must be refused gracefully by the converter)
p = os.path.join(HERE, "zip64.zip")
with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
    zi = zipfile.ZipInfo("big-zip64.txt")
    zi.flag_bits &= ~0x800
    with zf.open(zi, "w", force_zip64=True) as f:
        f.write(b"small data but zip64 headers\n")
print("wrote zip64.zip")

# 7) non-zip file to check graceful failure
w("not-a-zip.zip", b"this is not a zip archive at all\n")
