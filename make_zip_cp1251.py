# -*- coding: utf-8 -*-
"""
Create a ZIP archive whose entry names are encoded in CP1251 (Windows-1251),
the way old DOS/Windows archivers on Russian systems did it.

Normally ZIP tools write UTF-8 names and set general-purpose flag bit 11.
Here bit 11 stays clear and the raw name bytes are CP1251, so tools that
fall back to the system ANSI/OEM code page (e.g. Russian-locale Windows,
WinRAR, 7-Zip) display the names correctly.
"""
import binascii
import os
import shutil
import struct
import sys
import zlib
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(BASE, "files")                 # will contain Russian-named files
OUT = os.path.join(BASE, "russian-cp1251.zip")
CHECK = os.path.join(BASE, "extract-check")
REPORT = os.path.join(BASE, "verification_report.txt")

log_lines = []


def log(s):
    print(s)  # ASCII only
    log_lines.append(s)


def cp1251(s):
    return s.encode("cp1251")


# ---------------------------------------------------------------- source files
# name inside the archive / on disk  ->  content (UTF-8)
FILES = [
    ("Приветствие.txt",
     "Привет, мир!\n"
     "Этот файл имеет имя в кодировке CP1251 внутри архива.\n"),
    ("Заметки о проекте.txt",
     "Заметки о проекте\n"
     "-----------------\n"
     "1. Собрать архив с русскими именами файлов.\n"
     "2. Кодировка имён - Windows-1251 (CP1251).\n"
     "3. Флаг UTF-8 (бит 11) не установлен.\n"),
    ("Данные/список.csv",
     "№;наименение;количество\n"
     "1;яблоки;10\n"
     "2;груши;7\n"
     "3;сливы;25\n"),
]


def create_sources():
    if os.path.isdir(SRC):
        shutil.rmtree(SRC)
    for name, text in FILES:
        path = os.path.join(SRC, *name.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    log("Created source files in: %s" % SRC)


# ---------------------------------------------------------------- zip writing
def dos_datetime(ts):
    dt = datetime.fromtimestamp(ts)
    date = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
    time = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    return time, date


def deflate(data):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


class Entry(object):
    def __init__(self, name, src_path, is_dir=False):
        self.name = name            # logical name, e.g. "Данные/список.csv"
        self.name_bytes = cp1251(name)   # stored in the archive: CP1251 bytes
        self.is_dir = is_dir
        self.method = 0
        if is_dir:
            self.raw = b""
            self.crc = 0
            ts = os.path.getmtime(src_path)
        else:
            with open(src_path, "rb") as f:
                self.raw = f.read()
            self.crc = zlib.crc32(self.raw) & 0xFFFFFFFF
            ts = os.path.getmtime(src_path)
            self.method = 8
        self.data = b"" if is_dir else deflate(self.raw)
        self.usize = len(self.raw)
        self.csize = len(self.data)
        self.time, self.date = dos_datetime(ts)
        self.offset = None
        # CP1251 must be able to represent every character
        assert len(self.name_bytes) == len(self.name.encode("cp1251"))


def build_zip(entries):
    out = bytearray()
    # --- local file headers
    for e in entries:
        e.offset = len(out)
        out += struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,      # local file header signature
            20,              # version needed to extract (2.0)
            0,               # general purpose flags: UTF-8 bit (11) NOT set
            e.method,        # 0 = store, 8 = deflate
            e.time, e.date,
            e.crc, e.csize, e.usize,
            len(e.name_bytes), 0,   # name len, extra len
        )
        out += e.name_bytes
        out += e.data

    # --- central directory
    cd_start = len(out)
    for e in entries:
        out += struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,      # central directory signature
            0x0014,          # version made by: 2.0 / MS-DOS
            20,              # version needed
            0,               # flags: no UTF-8 bit
            e.method,
            e.time, e.date,
            e.crc, e.csize, e.usize,
            len(e.name_bytes), 0, 0,   # name, extra, comment lengths
            0,               # disk number start
            0,               # internal attributes
            0x10 if e.is_dir else 0x20,   # external attributes (DOS dir/archive bit)
            e.offset,        # relative offset of local header
        )
        out += e.name_bytes
    cd_size = len(out) - cd_start

    # --- end of central directory
    out += struct.pack(
        "<IHHHHIIH",
        0x06054B50,        # EOCD signature
        0, 0,              # this disk, disk with cd
        len(entries), len(entries),
        cd_size, cd_start,
        0,                 # comment length
    )
    return bytes(out)


# ---------------------------------------------------------------- verification
def find_eocd(buf):
    idx = buf.rfind(b"PK\x05\x06")
    if idx < 0:
        raise RuntimeError("EOCD not found")
    return idx


def parse_central(buf):
    idx = find_eocd(buf)
    (_, disk, cd_disk, n_disk, n_total,
     cd_size, cd_off, cmt) = struct.unpack("<IHHHHIIH", buf[idx:idx + 22])
    entries = []
    p = cd_off
    for _ in range(n_total):
        (sig, made, need, flags, method, t, d, crc, csz, usz,
         nlen, elen, clen, disk_, iattr, eattr, off) = struct.unpack(
            "<IHHHHHHIIIHHHHHII", buf[p:p + 46])
        assert sig == 0x02014B50, "bad central signature"
        name = buf[p + 46:p + 46 + nlen]
        entries.append(dict(name=name, flags=flags, method=method, crc=crc,
                            csize=csz, usize=usz, offset=off, eattr=eattr))
        p += 46 + nlen + elen + clen
    return entries


def extract_entry(buf, e):
    off = e["offset"]
    sig, need, flags, method, t, d, crc, csz, usz, nlen, elen = \
        struct.unpack("<IHHHHHIIIHH", buf[off:off + 30])
    assert sig == 0x04034B50, "bad local signature at %d" % off
    data = buf[off + 30 + nlen + elen: off + 30 + nlen + elen + e["csize"]]
    if method == 8:
        data = zlib.decompress(data, -15)
    elif method == 0:
        pass
    else:
        raise RuntimeError("unexpected method %d" % method)
    assert (zlib.crc32(data) & 0xFFFFFFFF) == e["crc"], "CRC mismatch"
    return data


def verify(entries, zip_bytes):
    ok = True
    log("")
    log("--- Verification ---")
    ce = parse_central(zip_bytes)
    log("Entries in central directory: %d" % len(ce))

    if os.path.isdir(CHECK):
        shutil.rmtree(CHECK)
    os.makedirs(CHECK)

    expected_names = [e.name for e in entries]
    for e_central, e_src in zip(ce, entries):
        name_b = e_central["name"]
        decoded = name_b.decode("cp1251")
        utf8_flag = bool(e_central["flags"] & 0x800)
        hexs = binascii.hexlify(name_b).decode("ascii")
        log_lines.append(
            "  name: %-28s utf8-flag=%s  bytes(cp1251)=%s"
            % (decoded, utf8_flag, " ".join(hexs[i:i + 2] for i in range(0, len(hexs), 2)))
        )
        if decoded != e_src.name:
            ok = False
            log("  !! name mismatch: %r != %r" % (decoded, e_src.name))
        if utf8_flag:
            ok = False
            log("  !! UTF-8 flag (bit 11) is set - should be clear")
        # name bytes must be identical to cp1251 encoding of the decoded name
        if name_b != decoded.encode("cp1251"):
            ok = False
            log("  !! name bytes are not valid CP1251 round-trip")

        # extract using raw cp1251-decoded names
        data = extract_entry(zip_bytes, e_central)
        dest = os.path.join(CHECK, *decoded.split("/"))
        if e_central["eattr"] & 0x10:
            os.makedirs(dest, exist_ok=True)
        else:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as f:
                f.write(data)
            with open(os.path.join(SRC, *decoded.split("/")), "rb") as f:
                if f.read() != data:
                    ok = False
                    log("  !! content mismatch for %s" % decoded)

    log("Raw byte check (name bytes == CP1251 encoding): "
        + ("PASS" if ok else "FAIL"))

    # what a UTF-8-centric reader (python zipfile) would show
    import zipfile
    with zipfile.ZipFile(OUT) as zf:
        shown = zf.namelist()
    log("")
    log("Names as seen by UTF-8-centric tools (mojibake expected):")
    for n in shown:
        log("  " + n)
    log("Extracted round-trip (CP1251 decode) into: %s" % CHECK)

    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines) + "\n")
    return ok


def main():
    create_sources()

    entries = []
    # the directory itself first, then its files, then top-level files
    dir_entry = Entry("Данные/", os.path.join(SRC, "Данные"), is_dir=True)
    entries.append(dir_entry)
    for name, _ in FILES:
        src = os.path.join(SRC, *name.split("/"))
        entries.append(Entry(name, src))

    zip_bytes = build_zip(entries)
    with open(OUT, "wb") as f:
        f.write(zip_bytes)
    log("Wrote archive: %s (%d bytes)" % (OUT, len(zip_bytes)))

    ok = verify(entries, zip_bytes)
    log("")
    log("RESULT: " + ("OK - names are stored in CP1251, UTF-8 flag clear"
                      if ok else "FAILED"))
    with open(REPORT, "a", encoding="utf-8") as f:
        f.write("\nRESULT: " + ("OK" if ok else "FAILED") + "\n")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
