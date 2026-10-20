#!/usr/bin/env python3
"""Создать MBR-заголовок с одним разделом в образе (для OVMF).

esp_mbr.py <image> <part_start_lba> <part_sectors>
"""
import sys

def main():
    img, start, sectors = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    with open(img, "r+b") as f:
        mbr = bytearray(512)
        # Partition entry 1: bootable, CHS-поля (фиктивные, LBA важнее),
        # тип 0x0E (FAT16 LBA), старт/размер в LBA.
        e = bytearray(16)
        e[0] = 0x80                     # bootable
        e[1:4] = b"\x20\x21\x00"        # begin CHS (мусор для QEMU/OVMF)
        e[4] = 0x0E                     # FAT16 LBA
        e[5:8] = b"\xfe\xff\xff"        # end CHS
        e[8:12] = start.to_bytes(4, "little")
        e[12:16] = sectors.to_bytes(4, "little")
        mbr[446:446 + 16] = e
        mbr[510:512] = b"\x55\xaa"
        f.seek(0)
        f.write(mbr)
    print(f"MBR ok: partition LBA {start}+{sectors}")

if __name__ == "__main__":
    main()
