# -*- coding: utf-8 -*-
"""
Independent verification of the conversion performed by
zip-cp1251-to-utf8.mjs.

For every (original, converted) pair it checks:
  * entry count / order / all non-name metadata identical
  * compressed data byte-for-byte identical
  * original name bytes, decoded as CP1251, equal the converted name bytes
    decoded as UTF-8 (strict)
  * EFS flag (bit 11) set in the converted archive, clear/irrelevant in the original
  * local file headers carry the same names as the central directory
  * the original fixture files were not modified (compared to a backup copy)
Writes the report to verify_report.txt (UTF-8).
"""
import hashlib
import os
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
BACKUP = os.path.join(HERE, "orig-backup")
REPORT = os.path.join(HERE, "verify_report.txt")

lines = []


def log(s):
    lines.append(s)


def read_central(path):
    buf = open(path, "rb").read()
    i = buf.rfind(b"PK\x05\x06")
    assert i >= 0, "no EOCD in " + path
    _, _, _, n_disk, n_total, cd_size, cd_off, clen = struct.unpack(
        "<IHHHHIIH", buf[i:i + 22])
    entries = []
    p = cd_off
    for _ in range(n_total):
        (sig, made, need, flags, method, t, d, crc, csz, usz,
         nlen, elen, cmlen, disk, iattr, eattr, off) = struct.unpack(
            "<IHHHHHHIIIHHHHHII", buf[p:p + 46])
        assert sig == 0x02014B50
        name = buf[p + 46:p + 46 + nlen]
        extra = buf[p + 46 + nlen:p + 46 + nlen + elen]
        entries.append(dict(name=name, extra=extra, flags=flags, method=method,
                            crc=crc, csize=csz, usize=usz, local=off,
                            eattr=eattr, time=t, date=d,
                            comment=buf[p + 46 + nlen + elen:
                                        p + 46 + nlen + elen + cmlen]))
        p += 46 + nlen + elen + cmlen
    comment = buf[i + 22:i + 22 + clen]
    return buf, entries, (n_disk, n_total, cd_size, cd_off, clen), comment


def local_name_and_data(buf, e):
    off = e["local"]
    (sig, need, flags, method, t, d, crc, csz, usz, nlen, elen) = struct.unpack(
        "<IHHHHHIIIHH", buf[off:off + 30])
    assert sig == 0x04034B50, "bad local header"
    name = buf[off + 30:off + 30 + nlen]
    data = buf[off + 30 + nlen + elen:off + 30 + nlen + elen + e["csize"]]
    return name, data, flags


def check_pair(orig, conv):
    obuf, oents, ometa, ocomment = read_central(orig)
    cbuf, cents, cmeta, ccomment = read_central(conv)
    problems = []
    if ocomment != ccomment:
        problems.append("archive comment changed: %r != %r" % (ocomment, ccomment))
    if len(oents) != len(cents):
        problems.append("entry count %d != %d" % (len(oents), len(cents)))
        return problems
    for i, (o, c) in enumerate(zip(oents, cents)):
        if o["method"] != c["method"]:
            problems.append("entry %d method changed" % i)
        if (o["crc"], o["csize"], o["usize"]) != (c["crc"], c["csize"], c["usize"]):
            problems.append("entry %d crc/size changed" % i)
        if o["eattr"] != c["eattr"] or o["time"] != c["time"] or o["date"] != c["date"]:
            problems.append("entry %d metadata changed" % i)
        if o["extra"] != c["extra"]:
            problems.append("entry %d extra field changed" % i)
        if not (c["flags"] & 0x800):
            problems.append("entry %d: EFS flag missing in converted archive" % i)
        if o["flags"] & 0x800:
            o_text = o["name"].decode("utf-8")
            expect = o["name"]
        else:
            o_text = o["name"].decode("cp1251")
            expect = o_text.encode("utf-8")
        if c["name"] != expect:
            problems.append("entry %d: name bytes %r != expected %r" % (i, c["name"], expect))
        try:
            c_text = c["name"].decode("utf-8")
        except UnicodeDecodeError as exc:
            problems.append("entry %d: converted name is not valid UTF-8 (%s)" % (i, exc))
            continue
        if c_text != o_text:
            problems.append("entry %d: text %r != %r" % (i, c_text, o_text))
        # local header names must agree with the central directory in *each* archive
        lname, ldata, _lflags = local_name_and_data(obuf, o)
        clname, cldata, _clflags = local_name_and_data(cbuf, c)
        if lname != o["name"]:
            problems.append("entry %d: original local name != original central name" % i)
        if clname != c["name"]:
            problems.append("entry %d: converted local name != converted central name" % i)
        if ldata != cldata:
            problems.append("entry %d: compressed data changed" % i)
        # data must still inflate to the same content and crc
        raw = zlib.decompress(cldata, -15) if c["method"] == 8 else cldata
        if (zlib.crc32(raw) & 0xFFFFFFFF) != c["crc"]:
            problems.append("entry %d: CRC mismatch after inflate" % i)
    return problems


def main():
    pairs = [
        ("cp1251-plain.zip", "cp1251-plain.utf8.zip"),
        ("cp1251-descriptors.zip", "cp1251-descriptors.utf8.zip"),
        ("mixed.zip", "mixed.utf8.zip"),
        ("utf8-names.zip", "utf8-names.utf8.zip"),
        ("ascii-names.zip", "ascii-names.utf8.zip"),
    ]
    ok = True
    log("=== conversion checks ===")
    for o, c in pairs:
        op = os.path.join(HERE, o)
        cp = os.path.join(HERE, c)
        if not os.path.exists(cp):
            log("FAIL %s -> %s: converted file missing" % (o, c))
            ok = False
            continue
        problems = check_pair(op, cp)
        if problems:
            ok = False
            log("FAIL %s -> %s" % (o, c))
            for p in problems:
                log("   " + p)
        else:
            _, cents, _, _ = read_central(cp)
            log("PASS %s -> %s (%d entries)" % (o, c, len(cents)))
            for e in cents:
                txt = e["name"].decode("utf-8")
                log("     %-34s utf8: %s   cp1251: %s" % (
                    txt,
                    " ".join("%02x" % b for b in e["name"]),
                    " ".join("%02x" % b for b in txt.encode("cp1251"))))

    log("")
    log("=== originals untouched (vs backup) ===")
    for name in sorted(os.listdir(BACKUP)):
        a = os.path.join(BACKUP, name)
        b = os.path.join(HERE, name)
        ha = hashlib.sha256(open(a, "rb").read()).hexdigest()
        hb = hashlib.sha256(open(b, "rb").read()).hexdigest()
        same = ha == hb
        ok = ok and same
        log("%s %s  sha256=%s" % ("PASS" if same else "FAIL", name, ha[:16]))

    log("")
    log("=== rejection checks ===")
    z64 = os.path.join(HERE, "zip64.zip.utf8.zip")
    if os.path.exists(z64):
        log("FAIL zip64 output was created (should have been refused)")
        ok = False
    else:
        log("PASS zip64.zip: refused, no output file left behind")
    naj = os.path.join(HERE, "not-a-zip.zip.utf8.zip")
    if os.path.exists(naj):
        log("FAIL not-a-zip output was created")
        ok = False
    else:
        log("PASS not-a-zip.zip: failed cleanly, no output file left behind")

    log("")
    log("=== reading a converted archive with a normal tool ===")
    import zipfile
    with zipfile.ZipFile(os.path.join(HERE, "cp1251-descriptors.utf8.zip")) as zf:
        for info in zf.infolist():
            data = zf.read(info)
            log("  %-40s %5d bytes  crc=%08x" % (info.filename, len(data), info.CRC))

    log("")
    log("RESULT: " + ("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED"))
    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED (see verify_report.txt)")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
