#!/usr/bin/env node
/**
 * zip-cp1251-to-utf8.mjs
 *
 * Rewrites old ZIP archives whose entry NAMES were encoded in CP1251
 * (Windows-1251, the code page used on Russian DOS/Windows systems) so that
 * the names are stored as UTF-8 with the EFS flag (bit 11) set, as required
 * by the modern APPNOTE spec.
 *
 * Guarantees:
 *   - File contents are never re-compressed: the raw data is copied byte-for-byte.
 *   - The input archive is only ever opened for reading and is never modified.
 *   - The result is written to a new file; it is built under a temporary name
 *     and renamed into place only after it verifies, so a failure can never
 *     destroy an existing file (and with --force the old output is replaced
 *     atomically rather than truncated).
 *   - Entries that already carry UTF-8 names (EFS flag) are copied unchanged.
 *   - ZIP64 archives are detected and refused: they cannot originate from the
 *     CP1251 era, and rewriting their offset tables needs care that is not
 *     worth the risk here.
 *
 * Usage:
 *   node zip-cp1251-to-utf8.mjs [options] <zip-or-directory> [more...]
 *
 * Options:
 *   -o, --output <file>     Output file (only with a single input file)
 *   -r, --recursive         Recurse into directories when collecting *.zip
 *   -f, --force             Overwrite an existing output file
 *   -n, --dry-run           Only report which names would be converted
 *   -l, --list              Show the per-entry name mapping
 *   -q, --quiet             Only print warnings and the final summary
 *   --fix-backslashes       Also convert '\' separators to '/' in names
 *   --keep-comments        Leave per-entry comments untouched (default: they
 *                           are converted together with the names, because the
 *                           EFS flag covers the comment field as well)
 *   --no-verify             Skip re-reading the data to re-check CRCs
 *   --no-fsync              Skip flushing each output file to disk
 *   -h, --help              Show this help
 *
 * Exit code: 0 = all ok, 1 = at least one file failed, 2 = bad usage
 */
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";

// ---------------------------------------------------------------- constants
const FLAG_DD = 0x0008; // data descriptor follows the entry data
const FLAG_UTF8 = 0x0800; // EFS: name is UTF-8 encoded

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const SIG_DD = 0x08074b50;
const SIG_DIGSIG = 0x05054b50; // optional "digital signature" record
const SIG_ZIP64_EOCD_LOCATOR = 0x07064b50;
const EXTRA_ZIP64 = 0x0001;

const COPY_BUF_SIZE = 1 << 20; // 1 MiB copy chunks

const utf8Strict = new TextDecoder("utf-8", { fatal: true });

// Windows-1251 is the whole point of this tool, so it uses one shared decoder,
// built at startup: a Node that lacks the needed ICU data then fails at once
// with a clear message instead of part-way through a batch.
let cp1251;
try {
  cp1251 = new TextDecoder("windows-1251");
} catch {
  fail("this Node build cannot decode windows-1251 (built without full ICU data)");
}

// crc32 of a buffer. node:zlib only grew zlib.crc32 in Node 20.15/22.2, so keep
// a table-based fallback for older runtimes. The capability check happens once,
// at load time; the table is only built if the fallback is actually used.
const nativeCrc32 = typeof zlib.crc32 === "function" ? zlib.crc32 : null;

let crcTable = null;
function crc32Fallback(buf) {
  if (crcTable === null) {
    crcTable = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[i] = c >>> 0;
    }
  }
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

const crc32 = nativeCrc32 ? (buf) => nativeCrc32(buf) >>> 0 : crc32Fallback;

// ---------------------------------------------------------------- helpers
function fail(msg) {
  throw new Error(msg);
}

function usage(code) {
  const help = [
    "Usage: node zip-cp1251-to-utf8.mjs [options] <zip-or-directory> [...]",
    "",
    "Converts ZIP entry names from CP1251 to UTF-8 (EFS flag). Contents are",
    "copied verbatim; input files are never modified. The converted archive is",
    "written to a new file and verified before it is put in place.",
    "",
    "Directories are scanned for *.zip files; this tool's own outputs",
    "(*.utf8.zip) are skipped so a batch can be re-run safely.",
    "",
    "  -o, --output <file>     Output file (single input only)",
    "  -r, --recursive         Recurse into directories (collects *.zip)",
    "  -f, --force             Overwrite existing output",
    "  -n, --dry-run           Report only, write nothing",
    "  -l, --list              Show per-entry name mapping",
    "  -q, --quiet             Only warnings and summary",
    "  --fix-backslashes       Convert backslash separators to '/'",
    "  --keep-comments         Do not convert per-entry comments",
    "  --no-verify             Skip re-reading the data to re-check CRCs",
    "                          (much faster for very large batches)",
    "  --no-fsync              Skip flushing each output to disk (faster)",
    "  -h, --help              This help",
  ].join("\n");
  process.stderr.write(help + "\n");
  process.exit(code);
}

function parseArgs(argv) {
  const opts = {
    recursive: false,
    force: false,
    dryRun: false,
    quiet: false,
    list: false,
    fixBackslashes: false,
    noVerify: false,
    noFsync: false,
    keepComments: false,
    output: null,
    inputs: [],
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "-h":
      case "--help":
        usage(0);
        break;
      case "-r":
      case "--recursive":
        opts.recursive = true;
        break;
      case "-f":
      case "--force":
        opts.force = true;
        break;
      case "-n":
      case "--dry-run":
        opts.dryRun = true;
        break;
      case "-q":
      case "--quiet":
        opts.quiet = true;
        break;
      case "-l":
      case "--list":
        opts.list = true;
        break;
      case "--fix-backslashes":
        opts.fixBackslashes = true;
        break;
      case "--no-verify":
        opts.noVerify = true;
        break;
      case "--no-fsync":
        opts.noFsync = true;
        break;
      case "--keep-comments":
        opts.keepComments = true;
        break;
      case "-o":
      case "--output":
        opts.output = argv[++i];
        break;
      default:
        if (a.startsWith("-")) {
          process.stderr.write("Unknown option: " + a + "\n");
          usage(2);
        }
        opts.inputs.push(a);
    }
  }
  if (opts.inputs.length === 0) usage(2);
  if (opts.output !== null && !opts.output) {
    process.stderr.write("--output requires a file name\n");
    usage(2);
  }
  if (opts.output && opts.inputs.length !== 1) {
    process.stderr.write("--output can only be used with a single input file\n");
    usage(2);
  }
  return opts;
}

function listZips(dir, recursive) {
  const out = [];
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, ent.name);
    if (ent.isDirectory()) {
      if (recursive) out.push(...listZips(p, true));
    } else if (ent.isFile() && ent.name.toLowerCase().endsWith(".zip")) {
      // skip this tool's own default outputs ("*.utf8.zip") when scanning a
      // directory, so a batch can be re-run/incremental without churn
      if (ent.name.toLowerCase().endsWith(".utf8.zip")) continue;
      out.push(p);
    }
  }
  return out;
}

function collectInputs(inputs, recursive) {
  const out = [];
  const seen = new Set();
  const push = (p) => {
    const r = path.resolve(p);
    const key = process.platform === "win32" ? r.toLowerCase() : r;
    if (!seen.has(key)) {
      seen.add(key);
      out.push(p);
    }
  };
  for (const input of inputs) {
    let st;
    try {
      st = fs.statSync(input);
    } catch {
      fail("input not found: " + input);
    }
    if (st.isDirectory()) {
      const zips = listZips(input, recursive);
      if (zips.length === 0)
        process.stderr.write("warn: no *.zip files in directory: " + input + "\n");
      for (const z of zips) push(z);
    } else {
      push(input); // explicit files are taken as-is (any extension)
    }
  }
  return out;
}

function readAt(fd, size, pos, len, what) {
  if (pos < 0 || len < 0 || pos + len > size)
    fail("truncated archive: " + (what || "read") + " beyond end of file");
  const buf = Buffer.allocUnsafe(len);
  let off = 0;
  while (off < len) {
    const n = fs.readSync(fd, buf, off, len - off, pos + off);
    if (n <= 0) fail("unexpected end of file while reading " + (what || "data"));
    off += n;
  }
  return buf;
}

function findEocd(fd, size) {
  if (size < 22) fail("not a ZIP archive (file too small)");
  const tailLen = Math.min(size, 22 + 0xffff);
  const tail = readAt(fd, size, size - tailLen, tailLen, "archive tail");
  const candidates = [];
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tail.readUInt32LE(i) !== SIG_EOCD) continue;
    const commentLen = tail.readUInt16LE(i + 20);
    const ends = i + 22 + commentLen;
    candidates.push({
      i,
      pos: size - tailLen + i,
      commentLen,
      fits: ends <= tail.length,
      atEof: ends === tail.length,
      trailing: tail.length - ends,
    });
  }
  if (candidates.length === 0)
    fail("not a ZIP archive (end of central directory record not found)");
  // Prefer a record whose comment runs exactly to the end of the file; only if
  // none exists (bytes were appended after the archive) fall back to the last
  // structurally plausible one, and let the caller warn about the loss.
  const chosen =
    candidates.find((c) => c.atEof) || candidates.find((c) => c.fits && c.commentLen >= 0);
  if (!chosen) fail("not a ZIP archive (end of central directory record not found)");
  const buf = tail.subarray(chosen.i, chosen.i + 22);
  const cdOffset = buf.readUInt32LE(16);
  const cdSize = buf.readUInt32LE(12);
  if (cdOffset > chosen.pos || cdOffset + cdSize > chosen.pos)
    fail(
      "inconsistent archive: the central directory (offset " + cdOffset + ", size " + cdSize +
        ") runs past the end record at " + chosen.pos
    );
  return { pos: chosen.pos, buf, trailing: Math.max(0, chosen.trailing) };
}

// scan extra-field records (id:u16, size:u16, data) for a ZIP64 marker
function hasZip64Extra(extra) {
  let p = 0;
  while (p + 4 <= extra.length) {
    const id = extra.readUInt16LE(p);
    const len = extra.readUInt16LE(p + 2);
    if (id === EXTRA_ZIP64 && len > 0) return true;
    p += 4 + len;
  }
  return false;
}

function parseCentralDir(cd, count, where) {
  const entries = [];
  let p = 0;
  for (let i = 0; i < count; i++) {
    if (p + 46 > cd.length) fail("central directory truncated at entry " + i + " " + where);
    if (cd.readUInt32LE(p) !== SIG_CENTRAL)
      fail("bad central directory signature at entry " + i + " " + where);
    const e = {
      versionMadeBy: cd.readUInt16LE(p + 4),
      versionNeeded: cd.readUInt16LE(p + 6),
      flags: cd.readUInt16LE(p + 8),
      method: cd.readUInt16LE(p + 10),
      time: cd.readUInt16LE(p + 12),
      date: cd.readUInt16LE(p + 14),
      crc: cd.readUInt32LE(p + 16),
      csize: cd.readUInt32LE(p + 20),
      usize: cd.readUInt32LE(p + 24),
      nameLen: cd.readUInt16LE(p + 28),
      extraLen: cd.readUInt16LE(p + 30),
      commentLen: cd.readUInt16LE(p + 32),
      diskStart: cd.readUInt16LE(p + 34),
      internalAttr: cd.readUInt16LE(p + 36),
      externalAttr: cd.readUInt32LE(p + 38),
      localOffset: cd.readUInt32LE(p + 42),
    };
    p += 46;
    if (p + e.nameLen + e.extraLen + e.commentLen > cd.length)
      fail("central directory truncated inside entry " + i + " " + where);
    e.name = Buffer.from(cd.subarray(p, p + e.nameLen));
    e.extra = Buffer.from(cd.subarray(p + e.nameLen, p + e.nameLen + e.extraLen));
    e.comment = Buffer.from(
      cd.subarray(p + e.nameLen + e.extraLen, p + e.nameLen + e.extraLen + e.commentLen)
    );
    entries.push(e);
    p += e.nameLen + e.extraLen + e.commentLen;
  }
  // Safety net against archives whose end record understates the entry count:
  // stop here and the remaining entries would be silently dropped.
  if (p + 4 <= cd.length && cd.readUInt32LE(p) === SIG_CENTRAL)
    fail(
      "the central directory holds more entries than the end record claims (" + count +
        "): refusing to convert, entries would be lost " + where
    );
  return entries;
}

// ---------------------------------------------------------------- planning
function planEntries(fd, size, entries, opts) {
  const warnings = [];
  const notes = [];
  const decoder = cp1251;

  const planned = entries.map((e, i) => {
    // ---- locate and cache the local file header (needed for writing too)
    const local = readAt(fd, size, e.localOffset, 30, "local header of entry " + i);
    if (local.readUInt32LE(0) !== SIG_LOCAL)
      fail("entry " + i + ": bad local file header signature at offset " + e.localOffset);
    e.local = local;
    e.localFlags = local.readUInt16LE(6);
    e.localNameLen = local.readUInt16LE(26);
    e.localExtraLen = local.readUInt16LE(28);
    e.localExtra = e.localExtraLen
      ? readAt(
          fd,
          size,
          e.localOffset + 30 + e.localNameLen,
          e.localExtraLen,
          "local extra field of entry " + i
        )
      : Buffer.alloc(0);

    // ---- ZIP64 is deliberately not supported (never produced by CP1251-era tools)
    if (
      e.csize === 0xffffffff ||
      e.usize === 0xffffffff ||
      e.localOffset === 0xffffffff ||
      hasZip64Extra(e.extra) ||
      hasZip64Extra(e.localExtra)
    )
      fail("entry " + i + " uses ZIP64 (64-bit) fields; ZIP64 archives are not supported");

    // ---- decide the new name (and comment)
    if (e.flags & FLAG_UTF8) {
      // already declares UTF-8: keep the bytes exactly as they are
      try {
        const text = utf8Strict.decode(e.name);
        if (e.comment.length) {
          try {
            utf8Strict.decode(e.comment);
          } catch {
            warnings.push(
              "entry " + i + ": the UTF-8 flag is set but the comment is not valid " +
                "UTF-8; leaving it untouched (use -e to reinterpret the archive)"
            );
          }
        }
        return {
          e,
          text,
          newName: e.name,
          newComment: e.comment,
          flags: e.flags,
          kind: "kept-utf8",
        };
      } catch {
        warnings.push(
          "entry " + i + ": UTF-8 flag set but name is not valid UTF-8; " +
            "converting as windows-1251"
        );
        // fall through and treat it as a legacy name
      }
    }
    let text = decoder.decode(e.name);
    if (opts.fixBackslashes) text = text.split("\\").join("/");
    const newName = Buffer.from(text, "utf8");
    if (newName.length > 0xffff)
      fail(
        "entry " + i + ": the name grows to " + newName.length +
          " bytes in UTF-8, over the 65535-byte ZIP limit (cannot be represented)"
      );
    // The EFS flag covers the comment field as well (APPNOTE 4.4.4), so a
    // legacy comment has to be converted together with the name.
    let newComment = e.comment;
    if (!opts.keepComments && e.comment.length) {
      newComment = Buffer.from(decoder.decode(e.comment), "utf8");
      if (newComment.length > 0xffff)
        fail(
          "entry " + i + ": the comment grows to " + newComment.length +
            " bytes in UTF-8, over the 65535-byte ZIP limit (use --keep-comments)"
        );
    }
    const allAscii = newName.equals(e.name);
    return {
      e,
      text,
      newName,
      newComment,
      flags: e.flags | FLAG_UTF8,
      kind: allAscii ? "flag-only" : "renamed",
    };
  });

  // sanity warnings (informational; names are never changed beyond the encoding)
  const seenNames = new Map();
  for (let i = 0; i < planned.length; i++) {
    const p = planned[i];
    if (p.e.name.length === 0) warnings.push("entry " + i + ": empty name");
    if (p.text.includes("\0")) warnings.push("entry " + i + ": name contains NUL byte");
    if (/\p{Cc}/u.test(p.text))
      warnings.push("entry " + i + ": name contains control characters");
    if (p.text.startsWith("/"))
      warnings.push("entry " + i + ": absolute path in name (" + JSON.stringify(p.text) + ")");
    if (p.text.split("/").includes(".."))
      warnings.push("entry " + i + ': ".." in name (' + JSON.stringify(p.text) + ")");
    if (p.text.includes("\\") && !opts.fixBackslashes)
      warnings.push(
        "entry " + i + ": backslash in name (" + JSON.stringify(p.text) +
          "); use --fix-backslashes if wanted"
      );
    if (seenNames.has(p.text))
      warnings.push(
        "duplicate name after conversion: " + JSON.stringify(p.text) +
          " (entries " + seenNames.get(p.text) + " and " + i + ")"
      );
    else seenNames.set(p.text, i);
    if (opts.list)
      notes.push(
        "map: " + p.e.name.toString("hex") + " -> " + JSON.stringify(p.text) +
          " [" + p.kind + "]"
      );
  }
  return { planned, warnings, notes };
}

// ---------------------------------------------------------------- writing
function makeWriter(fd) {
  const w = { fd, pos: 0 };
  w.write = (buf) => {
    let off = 0;
    while (off < buf.length) {
      off += fs.writeSync(fd, buf, off, buf.length - off);
    }
    w.pos += buf.length;
  };
  w.copy = (srcFd, size, pos, len) => {
    const tmp = Buffer.allocUnsafe(Math.min(COPY_BUF_SIZE, Math.max(len, 1)));
    let left = len;
    let p = pos;
    while (left > 0) {
      const n = fs.readSync(srcFd, tmp, 0, Math.min(tmp.length, left), p);
      if (n <= 0) fail("unexpected end of file while copying entry data");
      w.write(Buffer.from(tmp.subarray(0, n))); // defensive copy: buffer is reused
      p += n;
      left -= n;
    }
  };
  return w;
}

function pickDdLen(fd, size, dataEnd, nextLocalOffset, warn) {
  let hasSig = false;
  if (dataEnd + 4 <= size) {
    hasSig = readAt(fd, size, dataEnd, 4, "data descriptor").readUInt32LE(0) === SIG_DD;
  }
  let len = hasSig ? 16 : 12;
  if (nextLocalOffset === dataEnd + 12 || nextLocalOffset === dataEnd + 16) {
    if (nextLocalOffset !== dataEnd + len) {
      len = nextLocalOffset - dataEnd;
      warn("data descriptor length adjusted to " + len + " bytes to match the next entry");
    }
  }
  return len;
}

// Build the new archive at tmpPath, verify it, then move it to dstPath.
function convertFile(src, dst, opts) {
  const stats = {
    src,
    dst,
    entries: 0,
    renamed: 0,
    flagOnly: 0,
    keptUtf8: 0,
    warnings: [],
    notes: [],
    written: false,
    skipped: false,
  };
  const norm = (p) => {
    const r = path.resolve(p);
    return process.platform === "win32" ? r.toLowerCase() : r;
  };
  const inFd = fs.openSync(src, "r");
  let outFd = null;
  let tmpPath = null;
  let renamedInPlace = false;
  try {
    const size = fs.fstatSync(inFd).size;
    const eocd = findEocd(inFd, size);
    const e = eocd.buf;
    const disk = e.readUInt16LE(4);
    const cdDisk = e.readUInt16LE(6);
    const nDisk = e.readUInt16LE(8);
    const nTotal = e.readUInt16LE(10);
    const cdSize = e.readUInt32LE(12);
    const cdOffset = e.readUInt32LE(16);
    const commentLen = e.readUInt16LE(20);

    if (disk !== 0 || cdDisk !== 0 || nDisk !== nTotal)
      fail("multi-disk archives are not supported");
    if (nTotal === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff)
      fail("ZIP64 archive: not supported");
    if (eocd.pos >= 20) {
      const maybe = readAt(inFd, size, eocd.pos - 20, 4, "zip64 locator");
      if (maybe.readUInt32LE(0) === SIG_ZIP64_EOCD_LOCATOR)
        fail("ZIP64 archive (zip64 end of central directory locator found): not supported");
    }

    const cd = readAt(inFd, size, cdOffset, cdSize, "central directory");
    const entries = parseCentralDir(cd, nTotal, "in " + src);
    const plan = planEntries(inFd, size, entries, opts);
    const { planned } = plan;
    const warnings = plan.warnings;
    stats.warnings = warnings;
    stats.notes = plan.notes;
    // Nothing but an optional digital-signature record belongs between the end
    // of the central directory and the end record. A central-directory header
    // there means the entry count is understated and entries would be dropped.
    const gap = eocd.pos - (cdOffset + cdSize);
    if (gap > 0 && gap >= 4) {
      const probe = readAt(inFd, size, cdOffset + cdSize, 4, "region after the central directory");
      if (probe.readUInt32LE(0) === SIG_CENTRAL)
        fail(
          "the central directory holds more entries than the end record claims (" +
            nTotal + "): refusing to convert, entries would be dropped"
        );
      if (probe.readUInt32LE(0) === SIG_DIGSIG)
        warnings.push("an optional digital signature record is dropped");
      else
        warnings.push(
          gap + " byte(s) between the central directory and the end record are dropped"
        );
    }
    // Detect local file records that no central directory entry refers to: such
    // files are invisible to every reader, and would vanish from the result.
    if (planned.length) {
      let maxEnd = 0;
      for (const p of planned) {
        const end =
          p.e.localOffset + 30 + p.e.localNameLen + p.e.localExtraLen + p.e.csize;
        if (end > maxEnd) maxEnd = end;
      }
      // also look past a possible 12/16-byte data descriptor
      for (const at of [maxEnd, maxEnd + 12, maxEnd + 16]) {
        if (at + 4 > cdOffset || at + 4 > size) continue;
        const probe = readAt(inFd, size, at, 4, "region before the central directory");
        if (probe.readUInt32LE(0) === SIG_LOCAL)
          fail(
            "the archive holds a local file record that the central directory does not " +
              "reference: refusing to convert, that file would be dropped"
          );
      }
    }
    if (eocd.trailing > 0)
      warnings.push(
        eocd.trailing + " byte(s) after the end of central directory are dropped " +
          "(the input is not a plain ZIP from start to end)"
      );
    if (planned.length) {
      const firstLocal = Math.min(...planned.map((p) => p.e.localOffset));
      if (firstLocal > 0)
        warnings.push(
          firstLocal + " byte(s) before the first entry are dropped " +
            "(self-extracting stub?); the output is a plain ZIP archive"
        );
    }
    stats.entries = planned.length;
    if (commentLen > 0) {
      const cbuf = readAt(inFd, size, eocd.pos + 22, commentLen, "archive comment");
      if (cbuf.some((b) => b >= 0x80))
        warnings.push(
          "the archive comment is not plain ASCII; it is copied byte-for-byte and " +
            "modern tools will interpret it as UTF-8 (nothing can flag its encoding)"
        );
    }
    for (const p of planned) {
      if (p.kind === "renamed") stats.renamed++;
      else if (p.kind === "flag-only") stats.flagOnly++;
      else stats.keptUtf8++;
    }

    if (opts.dryRun) return stats;

    // ---- safety checks on the destination
    if (norm(src) === norm(dst))
      fail("refusing to write over the input file (a new file must be created)");
    if (!fs.existsSync(path.dirname(dst)))
      fail("output directory does not exist: " + path.dirname(dst));
    if (fs.existsSync(dst) && !opts.force) {
      // A previous run already produced this output. Nothing is ever left
      // half-written (temp file + rename), so skipping keeps large batches
      // idempotent and re-runnable.
      stats.skipped = true;
      stats.skipReason = "output already exists: " + dst + " (use --force to overwrite)";
      return stats;
    }

    // ---- write to a temporary file first
    tmpPath = path.join(
      path.dirname(dst),
      "." + path.basename(dst) + "." + process.pid + ".tmp"
    );
    outFd = fs.openSync(tmpPath, "w");
    const w = makeWriter(outFd);

    // local file headers + raw data (copied verbatim)
    const lh = Buffer.alloc(30);
    for (let i = 0; i < planned.length; i++) {
      const p = planned[i];
      const ent = p.e;
      const dataStart = ent.localOffset + 30 + ent.localNameLen + ent.localExtraLen;
      const dataEnd = dataStart + ent.csize;
      if (dataEnd > size)
        fail("entry " + i + ": data extends beyond end of file (truncated zip?)");

      ent.local.copy(lh, 0, 0, 30);
      // keep every local header field identical, except the name and its length
      // plus the EFS flag
      lh.writeUInt16LE(ent.localFlags | (p.flags & FLAG_UTF8 ? FLAG_UTF8 : 0), 6);
      lh.writeUInt16LE(p.newName.length, 26);
      p.newLocalOffset = w.pos;
      w.write(lh);
      w.write(p.newName);
      if (ent.localExtraLen) w.write(Buffer.from(ent.localExtra));
      if (ent.csize) w.copy(inFd, size, dataStart, ent.csize);

      if (ent.localFlags & FLAG_DD) {
        let nextOff = null;
        if (i + 1 < planned.length) {
          const nxt = planned[i + 1].e.localOffset;
          if (nxt === dataEnd + 12 || nxt === dataEnd + 16) nextOff = nxt;
        }
        const ddLen = pickDdLen(inFd, size, dataEnd, nextOff, (m) =>
          stats.warnings.push("entry " + i + ": " + m)
        );
        if (dataEnd + ddLen > size) fail("entry " + i + ": data descriptor beyond end of file");
        w.copy(inFd, size, dataEnd, ddLen);
      }
    }

    // central directory
    const cdStart = w.pos;
    const ch = Buffer.alloc(46);
    for (const p of planned) {
      const ent = p.e;
      ch.writeUInt32LE(SIG_CENTRAL, 0);
      ch.writeUInt16LE(ent.versionMadeBy, 4);
      ch.writeUInt16LE(ent.versionNeeded, 6);
      ch.writeUInt16LE(p.flags, 8);
      ch.writeUInt16LE(ent.method, 10);
      ch.writeUInt16LE(ent.time, 12);
      ch.writeUInt16LE(ent.date, 14);
      ch.writeUInt32LE(ent.crc, 16);
      ch.writeUInt32LE(ent.csize, 20);
      ch.writeUInt32LE(ent.usize, 24);
      ch.writeUInt16LE(p.newName.length, 28);
      ch.writeUInt16LE(ent.extra.length, 30);
      ch.writeUInt16LE(p.newComment.length, 32);
      ch.writeUInt16LE(ent.diskStart, 34);
      ch.writeUInt16LE(ent.internalAttr, 36);
      ch.writeUInt32LE(ent.externalAttr, 38);
      ch.writeUInt32LE(p.newLocalOffset, 42);
      w.write(ch);
      w.write(p.newName);
      if (ent.extra.length) w.write(ent.extra);
      if (p.newComment.length) w.write(p.newComment);
    }
    const cdSizeNew = w.pos - cdStart;

    // end of central directory (archive comment preserved)
    const eh = Buffer.alloc(22);
    eh.writeUInt32LE(SIG_EOCD, 0);
    eh.writeUInt16LE(0, 4);
    eh.writeUInt16LE(0, 6);
    eh.writeUInt16LE(planned.length, 8);
    eh.writeUInt16LE(planned.length, 10);
    eh.writeUInt32LE(cdSizeNew, 12);
    eh.writeUInt32LE(cdStart, 16);
    eh.writeUInt16LE(commentLen, 20);
    w.write(eh);
    if (commentLen) w.copy(inFd, size, eocd.pos + 22, commentLen);

    if (!opts.noFsync) fs.fsyncSync(outFd);
    fs.closeSync(outFd);
    outFd = null;
    stats.bytesWritten = w.pos;

    // ---- verify the temporary file, then put it in place
    verifyOutput(tmpPath, planned, !opts.noVerify);
    try {
      fs.renameSync(tmpPath, dst); // never destructive before this point
    } catch (err) {
      fail(
        "could not put the result in place (" + dst + "): " + err.message +
          " (is the target open in another program?)"
      );
    }
    renamedInPlace = true;
    stats.written = true;
    return stats;
  } finally {
    fs.closeSync(inFd);
    if (outFd !== null) {
      try {
        fs.closeSync(outFd);
      } catch {
        /* ignore */
      }
    }
    if (!renamedInPlace && tmpPath !== null) {
      try {
        if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
      } catch {
        /* ignore */
      }
    }
  }
}

// Re-open the produced archive and prove: every name decodes as UTF-8 to
// exactly the planned string, the EFS flag is set, and crc/sizes/metadata of
// the entries are untouched.
function verifyOutput(file, planned, verifyData) {
  const fd = fs.openSync(file, "r");
  try {
    const size = fs.fstatSync(fd).size;
    const eocd = findEocd(fd, size);
    const nTotal = eocd.buf.readUInt16LE(10);
    const cdSize = eocd.buf.readUInt32LE(12);
    const cdOffset = eocd.buf.readUInt32LE(16);
    const cd = readAt(fd, size, cdOffset, cdSize, "central directory of output");
    const entries = parseCentralDir(cd, nTotal, "in output");
    if (entries.length !== planned.length) fail("verify: entry count mismatch");
    for (let i = 0; i < entries.length; i++) {
      const en = entries[i];
      const p = planned[i];
      const text = utf8Strict.decode(en.name); // throws if not valid UTF-8
      if (text !== p.text) fail("verify: name mismatch at entry " + i);
      if (!en.name.equals(p.newName)) fail("verify: name bytes mismatch at entry " + i);
      if (!(en.flags & FLAG_UTF8)) fail("verify: EFS flag missing at entry " + i);
      if (en.flags !== p.flags) fail("verify: flags changed unexpectedly at entry " + i);
      if (en.crc !== p.e.crc || en.csize !== p.e.csize || en.usize !== p.e.usize)
        fail("verify: crc/size changed at entry " + i);
      if (en.method !== p.e.method || en.externalAttr !== p.e.externalAttr)
        fail("verify: entry metadata changed at entry " + i);
      if (!en.comment.equals(Buffer.from(p.newComment)) ||
          en.comment.length !== p.newComment.length)
        fail("verify: entry comment mismatch at entry " + i);

      // re-read the local header of the produced file: its name, name length
      // and flags must agree with the central directory
      const lh = readAt(fd, size, p.newLocalOffset, 30, "output local header");
      if (lh.readUInt32LE(0) !== SIG_LOCAL)
        fail("verify: bad local header signature at entry " + i);
      const lNameLen = lh.readUInt16LE(26);
      const lExtraLen = lh.readUInt16LE(28);
      if (lNameLen !== p.newName.length)
        fail("verify: local name length " + lNameLen + " != " + p.newName.length +
          " at entry " + i);
      if (!(lh.readUInt16LE(6) & FLAG_UTF8))
        fail("verify: local EFS flag missing at entry " + i);
      const lName = readAt(fd, size, p.newLocalOffset + 30, lNameLen, "output local name");
      if (!lName.equals(p.newName)) fail("verify: local name bytes mismatch at entry " + i);
      const dataStart = p.newLocalOffset + 30 + lNameLen + lExtraLen;
      if (lExtraLen !== p.e.localExtraLen)
        fail("verify: local extra length changed at entry " + i);
      // the copied data must still be readable and match the stored CRC
      // (methods other than store/deflate are copied verbatim but not verified)
      if (en.method === 0 || en.method === 8) {
        if (verifyData) {
          let raw = readAt(fd, size, dataStart, en.csize, "entry data");
          let inflated = true;
          if (en.method === 8) {
            try {
              raw = zlib.inflateRawSync(raw);
            } catch {
              inflated = false;
              fail(
                "verify: entry " + i + " of the result does not decompress; " +
                  "the source archive looks corrupt (the input was not modified)"
              );
            }
          }
          if (inflated && crc32(raw) !== en.crc)
            fail(
              "verify: entry " + i + " does not match its recorded CRC; the source " +
                "archive looks corrupt (use --no-verify to skip this check)"
            );
        }
      }
    }
  } finally {
    fs.closeSync(fd);
  }
}

// ---------------------------------------------------------------- main
function defaultOutput(input) {
  const dir = path.dirname(input);
  const base = path.basename(input);
  const stem = base.toLowerCase().endsWith(".zip") ? base.slice(0, -4) : base;
  return path.join(dir, stem + ".utf8.zip");
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  let inputs;
  try {
    inputs = collectInputs(opts.inputs, opts.recursive);
  } catch (err) {
    process.stderr.write("error: " + err.message + "\n");
    process.exit(1);
  }
  if (inputs.length === 0) {
    process.stderr.write("nothing to do\n");
    process.exit(2);
  }

  const totals = {
    files: 0,
    ok: 0,
    failed: 0,
    skipped: 0,
    entries: 0,
    renamed: 0,
    flagOnly: 0,
    keptUtf8: 0,
  };
  for (const src of inputs) {
    const dst = opts.output !== null ? opts.output : defaultOutput(src);
    try {
      const stats = convertFile(src, dst, opts);
      totals.files++;
      if (stats.skipped) {
        totals.skipped++;
        process.stdout.write("skip " + src + ": " + stats.skipReason + "\n");
        continue;
      }
      totals.ok++;
      totals.entries += stats.entries;
      totals.renamed += stats.renamed;
      totals.flagOnly += stats.flagOnly;
      totals.keptUtf8 += stats.keptUtf8;
      if (!opts.quiet) {
        const verb = opts.dryRun ? "plan" : "ok  ";
        const what = opts.dryRun ? "" : " -> " + dst + "  (" + stats.bytesWritten + " bytes)";
        process.stdout.write(
          verb + " " + src + what + "  [" + stats.entries + " entries: " +
            stats.renamed + " renamed, " + stats.flagOnly + " ascii-only, " +
            stats.keptUtf8 + " already-utf8]\n"
        );
        for (const n of stats.notes) process.stdout.write("  " + n + "\n");
      }
      for (const w of stats.warnings) process.stderr.write("  warn: " + w + "\n");
    } catch (err) {
      totals.files++;
      totals.failed++;
      process.stderr.write("FAIL " + src + ": " + err.message + "\n");
      // convertFile() removes its own temporary file; the destination and the
      // input are left untouched, so there is nothing to clean up here.
    }
  }

  process.stdout.write(
    "\nsummary: " + totals.ok + "/" + totals.files + " files ok" +
      (totals.skipped ? ", " + totals.skipped + " skipped" : "") +
      (totals.failed ? ", " + totals.failed + " failed" : "") +
      "; " + totals.entries + " entries: " + totals.renamed + " renamed, " +
      totals.flagOnly + " ascii-only (flag set), " + totals.keptUtf8 + " already-utf8\n"
  );
  process.exit(totals.failed ? 1 : 0);
}

main();
