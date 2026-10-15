# -*- coding: utf-8 -*-
"""Adversarial fixtures for reviewing zip-cp1251-to-utf8.mjs.

Covers: empty archive, many entries, local!=central extra fields, entries
listed out of order, SFX prefix stub, trailing junk after the EOCD,
understated entry count, over-long converted names and
per-entry/archive comments.
"""
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))


def deflate(data):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


class E:
    def __init__(self, name, data=b"", method=8, flags=0, descriptor=None,
                 is_dir=False, comment=b"", local_extra=b"", central_extra=b""):
        self.name = name
        self.data = data
        self.method = method
        self.flags = flags
        self.descriptor = descriptor
        self.is_dir = is_dir
        self.comment = comment
        self.local_extra = local_extra
        self.central_extra = central_extra


def build(entries, local_order=None, central_order=None, archive_comment=b"",
          stub=b"", trailing=b"", central_count=None):
    entries = list(entries)
    local_order = list(range(len(entries))) if local_order is None else local_order
    central_order = list(range(len(entries))) if central_order is None else central_order
    stub = bytes(stub)

    body = bytearray()
    offsets = {}
    for idx in local_order:
        e = entries[idx]
        comp = deflate(e.data) if e.method == 8 else e.data
        crc = zlib.crc32(e.data) & 0xFFFFFFFF
        flags = e.flags | (0x08 if e.descriptor else 0)
        l_csize = 0 if e.descriptor else len(comp)
        l_usize = 0 if e.descriptor else len(e.data)
        offsets[idx] = len(body) + len(stub)
        body += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, e.method,
                            0x6000, 0x5A21, crc, l_csize, l_usize,
                            len(e.name), len(e.local_extra))
        body += e.name + e.local_extra + comp
        if e.descriptor == "sig":
            body += struct.pack("<IIII", 0x08074B50, crc, len(comp), len(e.data))
        elif e.descriptor == "nosig":
            body += struct.pack("<III", crc, len(comp), len(e.data))
        e.crc, e.csize, e.usize, e.flags = crc, len(comp), len(e.data), flags

    cd_off = len(body) + len(stub)
    records = []
    for idx in central_order:
        e = entries[idx]
        rec = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 0x0014, 20, e.flags,
                          e.method, 0x6000, 0x5A21, e.crc, e.csize, e.usize,
                          len(e.name), len(e.central_extra), len(e.comment),
                          0, 0, 0x10 if e.is_dir else 0x20, offsets[idx])
        rec += e.name + e.central_extra + e.comment
        records.append(rec)
    n = len(records) if central_count is None else central_count
    cd_size = sum(len(r) for r in records[:n])
    for r in records[:n]:
        body += r

    body += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, n, n, cd_size, cd_off,
                        len(archive_comment))
    body += archive_comment + trailing
    return stub + bytes(body)


def w(path, data):
    with open(os.path.join(HERE, path), "wb") as f:
        f.write(data)
    print("wrote %-26s %6d bytes" % (path, len(data)))


def ru(s):
    return s.encode("cp1251")


def u8(s):
    return s.encode("utf-8")


# 1) valid but empty archive (no entries at all)
w("edge-empty.zip", build([]))

# 2) many entries: exercises offset arithmetic and per-entry rewriting
w("edge-many.zip", build([
    E(ru("Каталог %d/Файл %d.txt" % (i // 10, i)),
      data=("содержимое %d\n" % i).encode("utf-8"),
      method=(8 if i % 2 else 0))
    for i in range(300)
]))

# 3) extra fields that differ between local and central headers
extra_local = struct.pack("<HH", 0x5455, 5) + b"\x03\x11\x22\x33\x44"   # UT
extra_central = struct.pack("<HH", 0x7875, 4) + b"\x01\x02\x03\x04"     # ux
w("edge-extra-fields.zip", build([
    E(ru("Поля расширения.txt"), data=b"extra field test\n", method=8,
      local_extra=extra_local, central_extra=extra_central),
]))

# 4) central directory lists entries in a different order than the file body
w("edge-out-of-order.zip", build([
    E(ru("Первый.txt"), data=b"first\n"),
    E(ru("Второй.txt"), data=b"second\n"),
    E(ru("Третий.txt"), data=b"third\n"),
], local_order=[2, 0, 1], central_order=[0, 1, 2]))

# 4b) data descriptors combined with a scrambled layout: the descriptor-length
#     heuristic has no next entry to lean on, so this checks it stands alone
w("edge-descriptors-scrambled.zip", build([
    E(ru("Дескриптор первый.txt"), data=b"descriptor one\n", descriptor="sig"),
    E(ru("Дескриптор второй.txt"), data=b"descriptor two\n", descriptor="nosig",
      method=0),
    E(ru("Обычный третий.txt"), data=b"plain third\n"),
], local_order=[1, 2, 0], central_order=[2, 0, 1]))

# 5) SFX-style archive: 64-byte self-extracting stub before the zip data
w("edge-sfx.zip", build([
    E(ru("Внутри SFX.txt"), data=b"inside a self-extracting archive\n"),
    E(ru("Второй внутри.txt"), data=b"second entry\n"),
], stub=b"MZ" + b"\x00" * 62))

# 6) trailing junk after the EOCD
w("edge-trailing-junk.zip", build([
    E(ru("Файл с мусором.txt"), data=b"trailing junk follows\n"),
], trailing=b"\x00JUNKJUNK\x00"))

# 7) EOCD understates the number of entries (third one would be dropped)
w("edge-wrong-count.zip", build([
    E(ru("Первый.txt"), data=b"one\n"),
    E(ru("Второй.txt"), data=b"two\n"),
    E(ru("Третий потерянный.txt"), data=b"three - easy to lose!\n"),
], central_count=2))

# 8) name that becomes longer than the 16-bit name-length limit when UTF-8
w("edge-long-name.zip", build([
    E(ru("Ы" * 33000), data=b"name grows past 65535 bytes\n"),
]))

# 9) comments: per-entry (covered by the EFS flag) and archive-level
w("edge-comments.zip", build([
    E(ru("С комментарием.txt"), data=b"entry comment\n",
      comment=ru("Комментарий записи на русском")),
], archive_comment=ru("Комментарий архива")))
