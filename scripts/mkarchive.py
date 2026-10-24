#!/usr/bin/env python3
"""mkarchive.py: сборка boot-архива RLBA (протокол загрузки v3).

Продукт: единый файл (boot.cpio) — модуль [0] BootInfo v3:
  +0x00  RlbaHeader (64 байта, CRC32 полей до header_crc)
  +0x40  FLAT-образ бутстрапа (FLX1: заголовок + сегменты + данные)
  4K     каталог CatalogEntry[40] + таблица строк (имена/argv)
  4K     cpio-стрим newc (несжатый): данные файлов + TRAILER!!!

Данные файлов лежат в честном newc-стриме — стандартные утилиты
читают образ со смещения cpio_off; каталог RLBA — параллельная
структура быстрых смещений и чексумм (CRC32, IEEE 802.3 =
zlib.crc32). Раскладки структур — crates/boot/boot_archive.

Использование:
  mkarchive.py --flat ELF --init ELF [--init-args "a b"] \
               [--file NAME=ELF ...] --out boot.cpio [--xml boot_cfg.xml]

--xml: пропатчить archive_crc32="…" у пейлоада с archive="boot.cpio"
(заглушка сверяет CRC32 при чтении с ESP — битость ловится до EBS).
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
import zlib
from pathlib import Path

PAGE = 4096
RLBA_MAGIC = 0x4142_4C52  # "RLBA" LE
RLBA_VERSION = 3
FLAT_MAGIC = 0x3158_4C46  # "FLX1" LE
FLAT_VERSION = 1
FLAT_BASE = 0x4000_0000
MAX_CATALOG = 512
CATALOG_FLAG_INIT = 0x0001
HDR = struct.Struct("<IHHQQQIIQQII")  # RlbaHeader (64 байта)
CAT = struct.Struct("<IHHQQIII")  # поля CatalogEntry (36 байт)
CAT_PADDED = CAT.size + 4  # repr(C) Rust: 40 (tail pad до align 8)
FLX = struct.Struct("<IHHIIIII9I")  # FlatExecHeader (64 байта)
SEG = struct.Struct("<IIIIII")  # FlatSeg (24 байта)

PF_X, PF_W, PF_R = 1, 2, 4
PT_LOAD = 1


def elf64_segments(blob: bytes) -> tuple[int, list[dict]]:
    """PT_LOAD-сегменты ELF64 (LE) + e_entry. Без внешних зависимостей."""
    if len(blob) < 64 or blob[:4] != b"\x7fELF" or blob[4] != 2:
        raise SystemExit("mkarchive: не ELF64 (bootstrap/init)")
    (e_entry,) = struct.unpack_from("<Q", blob, 24)
    (e_phoff,) = struct.unpack_from("<Q", blob, 32)
    (e_phentsize,) = struct.unpack_from("<H", blob, 54)
    (e_phnum,) = struct.unpack_from("<H", blob, 56)
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", blob, off)
        if p_type != PT_LOAD:
            continue
        (p_offset,) = struct.unpack_from("<Q", blob, off + 0x08)
        (p_vaddr,) = struct.unpack_from("<Q", blob, off + 0x10)
        (p_filesz,) = struct.unpack_from("<Q", blob, off + 0x20)
        (p_memsz,) = struct.unpack_from("<Q", blob, off + 0x28)
        if p_memsz == 0:
            continue
        # W^X-перевод (единый протокол платформы: W+X теряет X).
        flags = 0b011 if p_flags & PF_W else (0b101 if p_flags & PF_X else 0b001)
        segs.append(
            {
                "vaddr": p_vaddr,
                "offset": p_offset,
                "filesz": p_filesz,
                "memsz": p_memsz,
                "flags": flags,
            }
        )
    if not segs:
        raise SystemExit("mkarchive: ELF без PT_LOAD")
    return e_entry, segs


def build_flat(elf: bytes) -> bytes:
    """ELF → FLAT-образ (FLX1): заголовок, таблица сегментов, данные."""
    entry, segs = elf64_segments(elf)
    if len(segs) > 4:
        raise SystemExit("mkarchive: >4 PT_LOAD у бутстрапа (FLAT предел)")
    load_base = FLAT_BASE
    for s in segs:
        if s["vaddr"] < load_base or s["vaddr"] % PAGE:
            raise SystemExit(f"mkarchive: сегмент не на 4K-границе: {s['vaddr']:#x}")
    mem_top = max(s["vaddr"] + s["memsz"] for s in segs) - load_base
    entry_off = entry - load_base
    if not 0 <= entry_off < mem_top:
        raise SystemExit("mkarchive: entry вне образа")

    # Раскладка: [FLX hdr 64][SEG×n][данные сегментов подряд].
    data_off = 64 + len(segs) * SEG.size
    out = bytearray()
    for s in segs:
        s["file_off"] = data_off
        out += elf[s["offset"] : s["offset"] + s["filesz"]]
        data_off += s["filesz"]
    seg_table = b"".join(
        SEG.pack(s["vaddr"], s["file_off"], s["filesz"], s["memsz"], s["flags"], 0)
        for s in segs
    )
    hdr_data = FLX.pack(
        FLAT_MAGIC,
        FLAT_VERSION,
        len(segs),
        entry_off,
        load_base,
        mem_top,
        64,
        0,  # image_crc (посчитаем после сборки)
        *([0] * 9),
    )
    image = hdr_data + seg_table + bytes(out)
    image_crc = zlib.crc32(image) & 0xFFFF_FFFF
    image = bytearray(image)
    struct.pack_into("<I", image, 24, image_crc)  # поле image_crc @ +0x18
    return bytes(image)


def cpio_newc(name: bytes, data: bytes, mode: int = 0o100644) -> bytes:
    """Одна запись cpio newc (110-байт ASCII-заголовок + имя + данные,
    паддинг до 4)."""
    namesize = len(name) + 1  # с нулём
    hdr = (
        b"070701"
        + b"%08X" % 0  # ino (не важен для RLBA-каталога)
        + b"%08X" % mode
        + b"%08X" % 0  # uid
        + b"%08X" % 0  # gid
        + b"%08X" % 1  # nlink
        + b"%08X" % 0  # mtime
        + b"%08X" % len(data)
        + b"%08X" % 0  # devmajor
        + b"%08X" % 0  # devminor
        + b"%08X" % 0  # rdevmajor
        + b"%08X" % 0  # rdevminor
        + b"%08X" % namesize
        + b"%08X" % 0  # check
    )
    assert len(hdr) == 110
    entry = hdr + name + b"\0"
    entry += b"\0" * ((-len(entry)) % 4)
    entry += data
    entry += b"\0" * ((-len(data)) % 4)
    return entry


CPIO_TRAILER = cpio_newc(b"TRAILER!!!", b"")


def build_archive(flat: bytes, files: list[dict]) -> bytes:
    """RLBA: заголовок + FLAT + каталог + строки + newc-стрим."""
    if not files or not any(f.get("init") for f in files):
        raise SystemExit("mkarchive: нет INIT-записи (аргумент --init)")
    if len(files) > MAX_CATALOG:
        raise SystemExit("mkarchive: слишком много файлов (предел каталога)")
    if sum(1 for f in files if f.get("init")) != 1:
        raise SystemExit("mkarchive: INIT-запись должна быть одна")

    # ── cpio-стрим: данные файлов; запоминаем смещения данных.
    cpio = bytearray()
    for f in files:
        f["data_off_in_cpio"] = len(cpio) + 110 + ((110 + len(f["name"]) + 1 + 3) // 4) * 0
        # Точная позиция данных: hdr(110) + name+0, паддинг к 4.
        prefix = 110 + len(f["name"]) + 1
        prefix += (-prefix) % 4
        f["data_off_in_cpio"] = len(cpio) + prefix
        cpio += cpio_newc(f["name"], f["data"], mode=0o100755 if f.get("init") else 0o100644)
    cpio += CPIO_TRAILER
    cpio += b"\0" * ((-len(cpio)) % 512)

    # ── FLAT (сразу за заголовком RLBA).
    flat_off = HDR.size
    flat_len = len(flat)

    # ── каталог + таблица строк (после FLAT, 4K-выравнивание).
    catalog_off = (flat_off + flat_len + PAGE - 1) // PAGE * PAGE
    names_off = catalog_off + len(files) * CAT_PADDED
    names = bytearray()
    entries = []
    for f in files:
        name_off = names_off + len(names)  # АБСОЛЮТНОЕ смещение
        names += f["name"] + b"\0"
        args_off = 0
        if f.get("args"):
            args_off = names_off + len(names)  # АБСОЛЮТНОЕ смещение
            names += f["args"].encode() + b"\0"
        entries.append(
            CAT.pack(
                name_off,
                len(f["name"]),
                CATALOG_FLAG_INIT if f.get("init") else 0,
                0,  # data_off — после сборки (абс. от начала образа)
                len(f["data"]),
                zlib.crc32(f["data"]) & 0xFFFF_FFFF,
                args_off,
                0,  # _pad
            )
            + b"\0" * 4  # tail-padding repr(C): 36 + 4 = 40 (align 8)
        )
    cpio_off = (names_off + len(names) + PAGE - 1) // PAGE * PAGE

    # ── финальная сборка.
    archive_len = cpio_off + len(cpio)
    blob = bytearray(archive_len)
    blob[flat_off : flat_off + flat_len] = flat
    blob[catalog_off : catalog_off + sum(len(e) for e in entries)] = b"".join(entries)
    blob[names_off : names_off + len(names)] = names
    blob[cpio_off : cpio_off + len(cpio)] = cpio
    # data_off записей — абсолютные (внутри newc); шаг — 40 (pad).
    for i, f in enumerate(files):
        abs_off = cpio_off + f["data_off_in_cpio"]
        struct.pack_into("<Q", blob, catalog_off + i * CAT_PADDED + 8, abs_off)

    # ── заголовок + CRC32.
    hdr_crc_span = struct.pack(
        "<IHHQQQIIQQ",
        RLBA_MAGIC,
        RLBA_VERSION,
        0,
        flat_off,
        flat_len,
        catalog_off,
        len(files),
        names_off,
        cpio_off,
        archive_len,
    )
    header = HDR.pack(
        RLBA_MAGIC,
        RLBA_VERSION,
        0,
        flat_off,
        flat_len,
        catalog_off,
        len(files),
        names_off,
        cpio_off,
        archive_len,
        zlib.crc32(hdr_crc_span) & 0xFFFF_FFFF,
        0,
    )
    blob[: HDR.size] = header
    return bytes(blob)


def patch_xml(xml_path: Path, archive_name: str, crc: int) -> None:
    """Пропатчить archive_crc32 у пейлоада с данным archive."""
    text = xml_path.read_text(encoding="utf-8")
    pat = re.compile(
        r'(<payload\b[^>]*\barchive="' + re.escape(archive_name) + r'"[^>]*?)'
        r'(\s+archive_crc32="[^"]*")?([^>]*>)',
        re.DOTALL,
    )

    def repl(m: re.Match) -> str:
        head, old, tail = m.group(1), m.group(2), m.group(3)
        attr = f' archive_crc32="0x{crc:08x}"'
        return head + attr + tail

    new, n = pat.subn(repl, text, count=1)
    if n == 0:
        raise SystemExit(f"mkarchive: в {xml_path} нет <payload archive={archive_name}>")
    xml_path.write_text(new, encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="RLBA boot-архив (протокол v3)")
    ap.add_argument("--flat", required=True, help="ELF бутстрапа (→ FLAT)")
    ap.add_argument("--init", required=True, help="ELF init-сервера (ET_EXEC)")
    ap.add_argument(
        "--init-args",
        default="",
        help="argv init из каталога (строка «arg1 arg2 …»)",
    )
    ap.add_argument(
        "--file",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="дополнительный файл образа (ELF/данные)",
    )
    ap.add_argument("--out", required=True, help="путь результата (boot.cpio)")
    ap.add_argument("--xml", help="boot_cfg.xml для патча archive_crc32")
    args = ap.parse_args()

    flat_elf = Path(args.flat).read_bytes()
    init_elf = Path(args.init).read_bytes()

    files = [
        {
            "name": b"init",
            "data": init_elf,
            "args": args.init_args or None,
            "init": True,
        }
    ]
    for spec in args.file:
        name, _, path = spec.partition("=")
        if not name or not path:
            raise SystemExit(f"mkarchive: --file ждал NAME=PATH, получил {spec!r}")
        files.append({"name": name.encode(), "data": Path(path).read_bytes()})

    archive = build_archive(build_flat(flat_elf), files)
    out = Path(args.out)
    out.write_bytes(archive)
    crc = zlib.crc32(archive) & 0xFFFF_FFFF
    print(
        f"mkarchive: {out} — {len(archive)} байт, "
        f"файлов {len(files)}, CRC32 0x{crc:08x}"
    )
    if args.xml:
        patch_xml(Path(args.xml), out.name, crc)
        print(f"mkarchive: {args.xml}: archive_crc32=0x{crc:08x} пропатчен")


if __name__ == "__main__":
    main()
