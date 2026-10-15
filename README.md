# zip-cp1251-to-utf8.mjs

Converts old ZIP archives whose entry **names** were encoded in **CP1251**
(Windows-1251 — the code page used by Russian DOS/Windows tools long ago)
into modern archives whose names are stored as **UTF-8** with the ZIP "EFS"
flag (general purpose bit 11) set.

The file **contents are never touched**: the compressed data streams are copied
byte-for-byte, so compression method, CRCs, timestamps, attributes, extra
fields and the archive comment are all preserved. Only the name bytes, their
length fields and the language-encoding flag are changed.

## The input is never modified

* The input archive is opened read-only.
* The result is written to a **new file** (default: `<name>.utf8.zip`).
* The new archive is built under a temporary name in the destination directory
  and only renamed into place **after it verifies**. A crash or a failed check
  can therefore never damage an existing file.
* If the destination already exists it is **skipped** (use `--force` to
  replace it), which makes repeated runs over a big folder idempotent.

## Usage

```bash
node zip-cp1251-to-utf8.mjs [options] <zip-or-directory> [more...]
```

| Option | Meaning |
| --- | --- |
| `-o, --output <file>` | Output path (only with a single input file) |
| `-r, --recursive` | Recurse into directories when collecting `*.zip` |
| `-f, --force` | Overwrite an existing output file |
| `-n, --dry-run` | Report what would be converted, write nothing |
| `-l, --list` | Show the per-entry mapping (old bytes -> new name) |
| `-e, --encoding <enc>` | Encoding of the old names (default `windows-1251`) |
| `-q, --quiet` | Only warnings and the summary |
| `--fix-backslashes` | Also turn DOS-style `\` separators into `/` |
| `--keep-comments` | Leave per-entry comments untouched |
| `--no-verify` | Skip re-reading the data to re-check CRCs (faster) |
| `--no-fsync` | Skip flushing each output to disk (faster) |
| `-h, --help` | Help |

Names **and per-entry comments** are converted, because the EFS flag covers the
comment field too (APPNOTE 4.4.4). The archive comment in the end record is
copied unchanged (it has no encoding flag).

Examples:

```bash
# one archive
node zip-cp1251-to-utf8.mjs "old archive.zip"
#   -> old archive.utf8.zip

# a whole tree, skipping outputs that already exist
node zip-cp1251-to-utf8.mjs -r --quiet D:\archives

# first look at what would change
node zip-cp1251-to-utf8.mjs -n -l "old archive.zip"

# custom destination
node zip-cp1251-to-utf8.mjs -o fixed.zip "old archive.zip"
```

Exit codes: `0` all good (skips are not failures), `1` at least one archive
failed, `2` bad usage.

## What is verified

After writing the temporary file the tool re-opens it and checks that

* every name is valid UTF-8 and decodes to exactly the intended string,
* the EFS flag is set (and nothing else in the flags changed),
* name lengths in the local headers agree with the central directory,
* entry comments were converted to valid UTF-8 as well,
* CRC-32, compressed and uncompressed sizes, method and attributes are
  identical to the source,
* compressed data still inflates to the recorded CRC (unless `--no-verify`).

The output is only renamed into place when all of that holds.

## Refused rather than silently damaged

These inputs are rejected with an explanation instead of producing a lossy result:

* **ZIP64** archives and multi-disk (split) archives.
* Archives whose end record **understates the entry count**, or that contain a
  local file record no central-directory entry refers to — both would silently
  lose files.
* Names (or comments) that grow past the 65535-byte ZIP limit when re-encoded.

Two lossy-but-harmless cases are converted **with a warning**: a self-extracting
stub before the first entry, and bytes appended after the end record. Both are
simply not part of the ZIP data, so the result is a plain, valid archive.

## Limitations

* **ZIP64** archives are refused with a clear message; they cannot come from
  the CP1251 era and rewriting their offset tables needs care.
* Multi-disk (split) archives are refused.
* Entries that already declare UTF-8 names are copied through unchanged, so
  mixed archives are handled correctly.
* The name encoding is an assumption, not a detection: `--encoding` selects a
  different one if a batch turns out not to be CP1251.

## Tests

`tests/make_test_zips.py` builds fixtures (plain CP1251, data descriptors with
and without signature, mixed UTF-8/CP1251, modern UTF-8, ASCII-only, ZIP64,
non-zip) and `tests/verify_conversion.py` re-parses the originals and the
results with an independent implementation, compares them field by field,
confirms the inputs are byte-identical to a backup, and reads a converted
archive with Python's `zipfile` as a "normal modern tool".

```bash
python tests/make_test_zips.py
node zip-cp1251-to-utf8.mjs tests/cp1251-plain.zip tests/cp1251-descriptors.zip \
     tests/mixed.zip tests/utf8-names.zip tests/ascii-names.zip
python tests/verify_conversion.py     # writes tests/verify_report.txt
```

`tests/make_edge_zips.py` + `tests/edge_checks.py` cover the nasty cases:
empty archives, 300 entries, local/central extra fields, entries listed out of
order, data descriptors with a scrambled layout, entry comments, an understated
entry count, an over-long name,
trailing junk and an SFX stub.

```bash
python tests/make_edge_zips.py
python tests/edge_checks.py           # writes tests/edge_report.txt
```
