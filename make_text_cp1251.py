# -*- coding: utf-8 -*-
"""
Create a plain text file whose contents are Russian text encoded in
CP1251 (Windows-1251), then verify the bytes on disk.
"""
import os

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, "text-cp1251.txt")          # ASCII-safe name
OUT_RU = os.path.join(BASE, "Текст CP1251.txt")      # same file, Russian name

TEXT = (
    "Сообщение в кодировке CP1251\r\n"
    "=============================\r\n"
    "\r\n"
    "Этот текст сохранён в кодировке Windows-1251 (CP1251),\r\n"
    "которая традиционно использовалась в русскоязычных версиях Windows.\r\n"
    "\r\n"
    "Строка со всеми особенностями:\r\n"
    "  Съешь ещё этих мягких французских булок, да выпей же чаю.\r\n"
    "  Ёлка, гроза, объём, щи, эхо — все буквы, включая «ё».\r\n"
    "\r\n"
    "Кодировка файла: Windows-1251. Кодовая страница: 1251.\r\n"
)

data = TEXT.encode("cp1251")

# --- sanity checks before writing
assert data.decode("cp1251") == TEXT, "cp1251 round-trip failed"
try:
    data.decode("utf-8")
    is_valid_utf8 = True
except UnicodeDecodeError:
    is_valid_utf8 = False

for path in (OUT, OUT_RU):
    with open(path, "wb") as f:   # raw bytes, no BOM, no transcoding
        f.write(data)

# --- verify what is actually on disk
with open(OUT, "rb") as f:
    on_disk = f.read()

print("File written        : %s" % os.path.basename(OUT))
print("Copy with RU name   : %s" % os.path.basename(OUT_RU))
print("Size                : %d bytes" % len(on_disk))
print("cp1251 round-trip   : %s" % ("PASS" if on_disk.decode("cp1251") == TEXT else "FAIL"))
print("is valid UTF-8      : %s (expected False)" % is_valid_utf8)
print("first 32 bytes (hex): " + " ".join("%02x" % b for b in on_disk[:32]))
print("encoding of 'Сообщ' : " + " ".join("%02x" % b for b in "Сообщ".encode("cp1251")))
