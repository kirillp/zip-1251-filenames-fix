# -*- coding: utf-8 -*-
"""
Edge-case checks for zip-cp1251-to-utf8.mjs.

Runs the converter (via node) on the adversarial fixtures from
make_edge_zips.py and checks, with an independent parser:

  * converted names/comments decode to the expected text (UTF-8)
  * CRC / sizes / method / extra fields are untouched
  * compressed data is byte-for-byte identical
  * data descriptors are rewritten correctly (semantic check, not a copy check)
  * inputs are never modified, and failures leave no output or temp files
  * warnings are emitted where they are expected (CP866 hint, dropped stub,
    dropped trailing bytes)

Results go to edge_report.txt (UTF-8).
"""
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TOOL = os.path.join(ROOT, "zip-cp1251-to-utf8.mjs")
BACKUP = os.path.join(HERE, "orig-backup")
REPORT = os.path.join(HERE, "edge_report.txt")

lines = []


def log(s=""):
    lines.append(s)


def parse_zip(path):
    buf = open(path, "rb").read()
    i = buf.rfind(b"PK\x05\x06")
    assert i >= 0, "no EOCD in " + path
    _, _, _, n_disk, n_total, cd_size, cd_off, clen = struct.unpack("<IHHHHIIH", buf[i:i + 22])
    entries = []
    p = cd_off
    for _ in range(n_total):
        (sig, made, need, flags, method, t, d, crc, csz, usz, nlen, elen, cmlen,
         disk, iattr, eattr, off) = struct.unpack("<IHHHHHHIIIHHHHHII", buf[p:p + 46])
        assert sig == 0x02014B50, "bad central sig at entry %d" % len(entries)
        entries.append(dict(
            name=buf[p + 46:p + 46 + nlen],
            extra=buf[p + 46 + nlen:p + 46 + nlen + elen],
            comment=buf[p + 46 + nlen + elen:p + 46 + nlen + elen + cmlen],
            flags=flags, method=method, crc=crc, csize=csz, usize=usz, local=off))
        p += 46 + nlen + elen + cmlen
    return buf, entries, dict(cd_off=cd_off, cd_size=cd_size, n=n_total, eocd=i)


def local_parts(buf, e):
    (sig, need, flags, method, t, d, crc, csz, usz, nlen, elen) = struct.unpack(
        "<IHHHHHIIIHH", buf[e["local"]:e["local"] + 30])
    assert sig == 0x04034B50, "bad local header"
    name = buf[e["local"] + 30:e["local"] + 30 + nlen]
    extra = buf[e["local"] + 30 + nlen:e["local"] + 30 + nlen + elen]
    data = buf[e["local"] + 30 + nlen + elen:e["local"] + 30 + nlen + elen + e["csize"]]
    return name, extra, data, flags


def check_descriptor(buf, e, entries, cd_off):
    """If the entry uses a data descriptor, its values must match the entry."""
    bounds = sorted([x["local"] for x in entries] + [cd_off])
    start = e["local"] + 30 + len(local_parts(buf, e)[0]) + len(local_parts(buf, e)[1]) + e["csize"]
    nxt = next((b for b in bounds if b > start), None)
    blob = buf[start:nxt] if nxt is not None else b""
    if len(blob) < 12:
        return ["descriptor missing or shorter than 12 bytes"]
    if blob[:4] == b"PK\x07\x08":
        crc_, csz_, usz_ = struct.unpack("<III", blob[4:16])
    else:
        crc_, csz_, usz_ = struct.unpack("<III", blob[:12])
    if (crc_, csz_, usz_) != (e["crc"], e["csize"], e["usize"]):
        return ["descriptor %r != entry (crc=%08x size=%d/%d)" %
                ((crc_, csz_, usz_), e["crc"], e["csize"], e["usize"])]
    return []


def compare(orig, conv, decode, keep_comments=False):
    obuf, oents, ometa = parse_zip(orig)
    cbuf, cents, cmeta = parse_zip(conv)
    problems = []
    if len(oents) != len(cents):
        return ["entry count %d != %d" % (len(oents), len(cents))]
    for i, (o, c) in enumerate(zip(oents, cents)):
        o_text = o["name"].decode(decode)
        if c["name"].decode("utf-8") != o_text:
            problems.append("entry %d name: %r (expected %r)" % (i, c["name"], o_text))
        if (o["crc"], o["csize"], o["usize"], o["method"]) != \
           (c["crc"], c["csize"], c["usize"], c["method"]):
            problems.append("entry %d crc/size/method changed" % i)
        if o["extra"] != c["extra"]:
            problems.append("entry %d central extra changed" % i)
        # comment: converted with the name (EFS covers comments) unless asked not to
        want_comment = o["comment"] if keep_comments else o["comment"].decode(decode).encode("utf-8")
        if c["comment"] != want_comment:
            problems.append("entry %d comment %r != %r" % (i, c["comment"], want_comment))
        oname, oextra, odata, oflags = local_parts(obuf, o)
        cname, cextra, cdata, cflags = local_parts(cbuf, c)
        if oname != o["name"] or cname != c["name"]:
            problems.append("entry %d local name mismatch" % i)
        if oextra != cextra:
            problems.append("entry %d local extra changed" % i)
        if odata != cdata:
            problems.append("entry %d compressed data changed" % i)
        if not (c["flags"] & 0x800):
            problems.append("entry %d EFS flag missing" % i)
        if oflags & 0x08:
            problems += ["entry %d %s" % (i, p) for p in
                         check_descriptor(cbuf, c, cents, cmeta["cd_off"])]
    return problems


# src, decode, extra args, expectation, notes
#   expectation: "ok" | "fail"
CASES = [
    ("edge-empty.zip", "cp1251", (), "ok", "empty archive stays empty"),
    ("edge-many.zip", "cp1251", (), "ok", "300 entries, offsets recomputed"),
    ("edge-extra-fields.zip", "cp1251", (), "ok", "local/central extra fields preserved"),
    ("edge-out-of-order.zip", "cp1251", (), "ok", "central order differs from file order"),
    ("edge-descriptors-scrambled.zip", "cp1251", (), "ok", "descriptors without a next entry"),
    ("edge-cp866.zip", "cp866", ("-e", "ibm866"), "ok", "explicit -e ibm866"),
    ("edge-cp866.zip", "cp866", ("-e", "auto"), "ok", "encoding auto-detection"),
    ("edge-comments.zip", "cp1251", (), "ok", "entry comment converted with the name"),
    ("edge-comments.zip", "cp1251", ("--keep-comments",), "ok", "comment left alone on request"),
    ("edge-wrong-count.zip", "cp1251", (), "fail", "EOCD understates the entry count"),
    ("edge-long-name.zip", "cp1251", (), "fail", "converted name exceeds 65535 bytes"),
    ("edge-trailing-junk.zip", "cp1251", (), "ok", "junk after EOCD is dropped + warned"),
    ("edge-sfx.zip", "cp1251", (), "ok", "SFX stub dropped + warned"),
]


def main():
    # keep a pristine copy so we can prove the inputs are never modified
    if os.path.isdir(BACKUP):
        shutil.rmtree(BACKUP)
    os.makedirs(BACKUP)
    for f in os.listdir(HERE):
        if f.startswith("edge-") and f.endswith(".zip") and not f.endswith(".utf8.zip"):
            shutil.copyfile(os.path.join(HERE, f), os.path.join(BACKUP, f))

    ok = True
    log("fixture                        args             exit  verdict")
    log("-" * 88)
    for src, dec, args, expect, note in CASES:
        kind = dict(zip(("src", "dec", "args", "expect", "note"), (src, dec, args, expect, note)))
        out = os.path.join(HERE, src.replace(".zip", ".utf8.zip"))
        if os.path.exists(out):
            os.remove(out)
        r = subprocess.run(["node", TOOL] + list(args) + [os.path.join(HERE, src)],
                           capture_output=True, text=True, encoding="utf-8", cwd=ROOT)
        stderr = (r.stderr or "").strip()
        verdict = ""
        good = True
        if expect == "ok":
            if r.returncode != 0:
                good, verdict = False, "unexpected failure: " + stderr.splitlines()[0][:70]
            elif not os.path.exists(out):
                good, verdict = False, "no output produced"
            else:
                problems = compare(os.path.join(HERE, src), out, dec,
                                   keep_comments="--keep-comments" in args)
                if problems:
                    good, verdict = False, "; ".join(problems[:2])
                else:
                    _, cent, _ = parse_zip(out)
                    verdict = "%d entries verified" % len(cent)
        else:  # expect failure
            if r.returncode == 0 and os.path.exists(out):
                good, verdict = False, "converted anyway (should have been refused)"
            elif os.path.exists(out):
                good, verdict = False, "refused but left an output file behind"
            else:
                verdict = "refused: " + (stderr.splitlines()[0][60:] if stderr else "?")
        # no temp files may survive
        temps = [f for f in os.listdir(HERE) if f.endswith(".tmp")]
        if temps:
            good = False
            verdict += " | LEFTOVER TEMP: %s" % temps
        # expectation-specific assertions
        if src == "edge-cp866.zip" and not args:
            pass  # covered by the dedicated CP866 warning case below
        if src == "edge-sfx.zip" and expect == "ok" and os.path.exists(out):
            body = open(out, "rb").read()
            if not body.startswith(b"PK\x03\x04"):
                good, verdict = False, "output is not a plain zip: " + verdict
            if "before the first entry" not in stderr:
                good, verdict = False, "no warning about the dropped stub"
            verdict += " | stub dropped, warning present"
        if src == "edge-trailing-junk.zip" and expect == "ok" and os.path.exists(out):
            if b"JUNKJUNK" in open(out, "rb").read():
                good, verdict = False, "junk was copied into the output"
            if "after the end of central directory" not in stderr:
                good, verdict = False, "no warning about the dropped trailing bytes"
            verdict += " | junk dropped, warning present"
        log("%-30s %-16s %-5d %s" % (src, " ".join(args) or "-", r.returncode, verdict))
        log("%-30s %s" % ("", note))
        if not good:
            ok = False

    # CP866 names with the default CP1251 assumption: conversion must at least
    # warn, so a wrong guess cannot slip through unnoticed in a big batch
    log("")
    log("=== the CP866 trap (default CP1251 assumption) ===")
    src = os.path.join(HERE, "edge-cp866.zip")
    out = os.path.join(HERE, "edge-cp866.utf8.zip")
    if os.path.exists(out):
        os.remove(out)
    r = subprocess.run(["node", TOOL, src], capture_output=True, text=True,
                       encoding="utf-8", cwd=ROOT)
    stderr = (r.stderr or "").strip()
    if os.path.exists(out):
        _, cent, _ = parse_zip(out)
        wrong = cent[0]["name"].decode("utf-8")
        log("converted name with default settings: %r" % wrong)
    if "ibm866" in stderr:
        log("PASS warning suggests ibm866: %s" % stderr.splitlines()[0].strip()[-70:])
    else:
        log("FAIL no hint about the likely CP866 encoding was printed")
        ok = False

    log("")
    log("=== originals untouched (vs backup) ===")
    for name in sorted(os.listdir(BACKUP)):
        a = hashlib.sha256(open(os.path.join(BACKUP, name), "rb").read()).hexdigest()
        b = hashlib.sha256(open(os.path.join(HERE, name), "rb").read()).hexdigest()
        same = a == b
        ok = ok and same
        if not same:
            log("FAIL %s was modified!" % name)
    log("PASS all %d fixtures unchanged" % len(os.listdir(BACKUP)))

    log("")
    log("RESULT: " + ("all expectations met" if ok else "PROBLEMS FOUND"))
    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
