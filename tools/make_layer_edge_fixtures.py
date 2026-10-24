"""Create extra wire fixtures, then validate them with the independent TSK oracle.

Generated FAT images exercise variants, Unicode LFNs and fragmented chains.
NTFS disk images wrap the unchanged dfVFS volume in MBR/GPT and libewf E01.
This development tool is not used by the Rust implementation or normal tests.
"""
import argparse
import gzip
import hashlib
import math
from pathlib import Path
import struct
import uuid
import zlib

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests/fixtures/layers"


def p16(data, offset, value): struct.pack_into("<H", data, offset, value)
def p32(data, offset, value): struct.pack_into("<I", data, offset, value)
def p64(data, offset, value): struct.pack_into("<Q", data, offset, value)


def short_entry(name, cluster, size, is_dir=False):
    entry = bytearray(32)
    entry[:11] = name
    entry[11] = 0x10 if is_dir else 0x20
    p16(entry, 20, cluster >> 16)
    p16(entry, 26, cluster & 0xFFFF)
    p32(entry, 28, size)
    for offset in (16, 18, 24): p16(entry, offset, 0x21)  # 1980-01-01
    return entry


def long_entries(name, short):
    encoded = name.encode("utf-16-le") + b"\0\0"
    encoded += b"\xff\xff" * ((-len(encoded) // 2) % 13)
    checksum = 0
    for byte in short[:11]: checksum = (((checksum >> 1) | (checksum << 7)) + byte) & 0xFF
    result = bytearray()
    for index in reversed(range(len(encoded) // 26)):
        entry = bytearray(32)
        entry[0] = index + 1 | (0x40 if index == len(encoded) // 26 - 1 else 0)
        entry[11] = 0xF
        entry[13] = checksum
        units = encoded[index * 26:(index + 1) * 26]
        for unit, offset in enumerate((1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30)):
            entry[offset:offset + 2] = units[unit * 2:unit * 2 + 2]
        result.extend(entry)
    return result


def fat(bits):
    total, reserved, fat_sectors, spc, roots = (32768, 1, 64, 2, 512) if bits == 16 else (69632, 32, 544, 1, 0)
    root_sectors = math.ceil(roots * 32 / 512)
    first_data = reserved + 2 * fat_sectors + root_sectors
    image = bytearray(total * 512)
    image[:3] = b"\xeb\x58\x90"
    image[3:11] = b"INODEX  "
    p16(image, 11, 512)
    image[13] = spc
    p16(image, 14, reserved)
    image[16] = 2
    p16(image, 17, roots)
    image[21] = 0xF8
    p16(image, 24, 32)
    p16(image, 26, 64)
    if bits == 16:
        p16(image, 19, total)
        p16(image, 22, fat_sectors)
        image[36], image[38] = 0x80, 0x29
        p32(image, 39, 0x10203040)
        image[43:54] = b"INODEX_F16 "
        image[54:62] = b"FAT16   "
    else:
        p32(image, 32, total)
        p32(image, 36, fat_sectors)
        p32(image, 44, 2)
        p16(image, 48, 1)
        p16(image, 50, 6)
        image[64], image[66] = 0x80, 0x29
        p32(image, 67, 0x10203040)
        image[71:82] = b"INODEX_F32 "
        image[82:90] = b"FAT32   "
        p32(image, 512, 0x41615252)
        p32(image, 512 + 484, 0x61417272)
        p32(image, 512 + 488, 0xFFFFFFFF)
        p32(image, 512 + 492, 0xFFFFFFFF)
        p32(image, 512 + 508, 0xAA550000)
    image[510:512] = b"\x55\xaa"
    if bits == 32:
        image[6 * 512:7 * 512] = image[:512]
        image[7 * 512:8 * 512] = image[512:1024]
    table = bytearray(fat_sectors * 512)
    put = p16 if bits == 16 else p32
    eoc = 0xFFFF if bits == 16 else 0x0FFFFFFF
    put(table, 0, eoc - 7)
    put(table, bits // 8, eoc)
    if bits == 32: put(table, 2 * 4, eoc)
    cluster_size = spc * 512
    payload = (bytes(range(251)) * 523)[:131113]
    chain = [3 + 2 * index for index in range(math.ceil(len(payload) / cluster_size))]
    for index, cluster in enumerate(chain):
        put(table, cluster * (bits // 8), chain[index + 1] if index + 1 < len(chain) else eoc)
        start = (first_data + (cluster - 2) * spc) * 512
        part = payload[index * cluster_size:(index + 1) * cluster_size]
        image[start:start + len(part)] = part
    put(table, 4 * (bits // 8), eoc)
    put(table, 6 * (bits // 8), eoc)
    for index in range(2):
        offset = (reserved + index * fat_sectors) * 512
        image[offset:offset + len(table)] = table
    root_offset = first_data * 512 if bits == 32 else (reserved + 2 * fat_sectors) * 512
    short = short_entry(b"RESUME~1TXT", 3, len(payload))
    directory = long_entries("R\u00e9sum\u00e9 long filename.txt", short) + short
    directory += short_entry(b"NESTED     ", 4, 0, True)
    directory += short_entry(b"EMPTY   TXT", 0, 0)
    image[root_offset:root_offset + len(directory)] = directory
    nested = short_entry(b".          ", 4, 0, True) + short_entry(b"..         ", 0, 0, True)
    nested += short_entry(b"HELLO   TXT", 6, 16)
    offset = (first_data + 2 * spc) * 512
    image[offset:offset + len(nested)] = nested
    offset = (first_data + 4 * spc) * 512
    image[offset:offset + 16] = b"nested contents\n"
    return bytes(image)


def ntfs_disk(gpt):
    volume = gzip.decompress((OUT / "ntfs.raw.gz").read_bytes())
    total, start = 11264, 2048
    image = bytearray(total * 512)
    image[start * 512:start * 512 + len(volume)] = volume
    image[510:512] = b"\x55\xaa"
    image[446 + 4] = 0xEE if gpt else 7
    image[446] = 0 if gpt else 0x80
    p32(image, 454, 1 if gpt else start)
    p32(image, 458, total - 1 if gpt else len(volume) // 512)
    if gpt:
        table = bytearray(128 * 128)
        offset = 2 * 128  # Partition slot 3, to test preserved entry indices.
        table[offset:offset + 16] = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7").bytes_le
        table[offset + 16:offset + 32] = uuid.UUID("12345678-1234-4321-aabb-0123456789ab").bytes_le
        p64(table, offset + 32, start)
        p64(table, offset + 40, start + len(volume) // 512 - 1)
        name = "NTFS evidence \u2603".encode("utf-16-le")
        table[offset + 56:offset + 56 + len(name)] = name
        for lba, other, array in [(1, total - 1, 2), (total - 1, 1, total - 33)]:
            header = bytearray(512)
            header[:8] = b"EFI PART"
            p32(header, 8, 0x10000)
            p32(header, 12, 92)
            for offset, value in [(24, lba), (32, other), (40, 34), (48, total - 34), (72, array)]: p64(header, offset, value)
            header[56:72] = uuid.UUID("11111111-2222-3333-aaaa-bbbbbbbbbbbb").bytes_le
            p32(header, 80, 128)
            p32(header, 84, 128)
            p32(header, 88, zlib.crc32(table))
            p32(header, 16, zlib.crc32(header[:92]))
            image[lba * 512:(lba + 1) * 512] = header
            image[array * 512:array * 512 + len(table)] = table
    return bytes(image)


def crc32c(seed, data):
    for byte in data:
        seed ^= byte
        for _ in range(8): seed = (seed >> 1) ^ (0x82F63B78 if seed & 1 else 0)
    return seed


def ext_inode_location(image, number):
    block_size = 1024 << struct.unpack_from("<I", image, 1024 + 24)[0]
    inode_size = struct.unpack_from("<H", image, 1024 + 88)[0]
    table = struct.unpack_from("<I", image, 2 * block_size + 8)[0]
    return table * block_size + (number - 1) * inode_size


def ext2_indirect():
    image = bytearray(gzip.decompress((OUT.parent / "ext2.raw.gz").read_bytes()))
    location = ext_inode_location(image, 14)
    image[location + 40:location + 100] = bytes(60)
    free = iter(range(3000, 3100))
    allocated = []

    def allocate():
        block = next(free)
        allocated.append(block)
        image[block * 1024:(block + 1) * 1024] = bytes(1024)
        return block

    def pointer(offset):
        value = struct.unpack_from("<I", image, offset)[0]
        if not value:
            value = allocate()
            p32(image, offset, value)
        return value

    for logical in [0, 11, 12, 13, 267, 268, 65803, 65804]:
        if logical < 12:
            target = location + 40 + logical * 4
        else:
            relative = logical - 12
            for depth in range(1, 4):
                capacity = 256 ** depth
                if relative < capacity:
                    block = pointer(location + 40 + (11 + depth) * 4)
                    for level in reversed(range(depth)):
                        index, relative = divmod(relative, 256 ** level)
                        target = block * 1024 + index * 4
                        if level: block = pointer(target)
                    break
                relative -= capacity
        block = allocate()
        p32(image, target, block)
        pattern = ("logical:%d|" % logical).encode()
        image[block * 1024:(block + 1) * 1024] = (pattern * (1024 // len(pattern) + 1))[:1024]
    p32(image, location + 4, 65805 * 1024)
    p32(image, location + 108, 0)
    p32(image, location + 28, len(allocated) * 2)
    bitmap = struct.unpack_from("<I", image, 2048)[0] * 1024
    for block in allocated:
        bit = block - 1
        image[bitmap + bit // 8] |= 1 << (bit % 8)
    p32(image, 1024 + 12, struct.unpack_from("<I", image, 1024 + 12)[0] - len(allocated))
    p16(image, 2048 + 12, struct.unpack_from("<H", image, 2048 + 12)[0] - len(allocated))
    return bytes(image)


def ext4_extent():
    image = bytearray(gzip.decompress((OUT / "ext4.raw.gz").read_bytes()))
    location = ext_inode_location(image, 14)
    image[location + 40:location + 100] = bytes(60)
    for offset, value in [(40, 0xF30A), (42, 1), (44, 4), (46, 1)]: p16(image, location + offset, value)
    p32(image, location + 56, 3000)
    p32(image, location + 4, 269 * 1024)
    p32(image, location + 108, 0)
    p32(image, location + 28, 8)
    p32(image, location + 32, 0x80000)
    leaf = bytearray(1024)
    for offset, value in [(0, 0xF30A), (2, 3), (4, 84), (6, 0)]: p16(leaf, offset, value)
    for index, (logical, length, physical) in enumerate([(0, 1, 3001), (12, 1, 3002), (268, 32769, 3003)]):
        offset = 12 + 12 * index
        p32(leaf, offset, logical)
        p16(leaf, offset + 4, length)
        p32(leaf, offset + 8, physical)
        image[physical * 1024:(physical + 1) * 1024] = bytes([0x41 + index]) * 1024
    fs_seed = crc32c(0xFFFFFFFF, image[1024 + 104:1024 + 120])
    generation = struct.unpack_from("<I", image, location + 100)[0]
    inode_seed = crc32c(crc32c(fs_seed, struct.pack("<I", 14)), struct.pack("<I", generation))
    p32(leaf, 1020, crc32c(inode_seed, leaf[:1020]))
    image[3000 * 1024:3001 * 1024] = leaf
    p16(image, location + 124, 0)
    p16(image, location + 130, 0)
    checksum = crc32c(inode_seed, image[location:location + 256])
    p16(image, location + 124, checksum & 0xFFFF)
    p16(image, location + 130, checksum >> 16)
    bitmap_block = struct.unpack_from("<I", image, 2048)[0]
    bitmap = bitmap_block * 1024
    for block in range(3000, 3004):
        bit = block - 1
        image[bitmap + bit // 8] |= 1 << (bit % 8)
    bitmap_checksum = crc32c(fs_seed, image[bitmap:bitmap + 1024])
    p16(image, 2048 + 24, bitmap_checksum & 0xFFFF)
    p16(image, 2048 + 56, bitmap_checksum >> 16)
    p16(image, 2048 + 12, struct.unpack_from("<H", image, 2048 + 12)[0] - 4)
    p16(image, 2048 + 30, 0)
    p16(image, 2048 + 30, crc32c(crc32c(fs_seed, struct.pack("<I", 0)), image[2048:2112]) & 0xFFFF)
    p32(image, 1024 + 12, struct.unpack_from("<I", image, 1024 + 12)[0] - 4)
    p32(image, 1024 + 1020, crc32c(0xFFFFFFFF, image[1024:2044]))
    return bytes(image)


def ntfs_attribute_list():
    image = bytearray(gzip.decompress((OUT / "ntfs.raw.gz").read_bytes()))

    def unprotect(number):
        record = bytearray(image[16384 + number * 1024:16384 + (number + 1) * 1024])
        offset, count = struct.unpack_from("<HH", record, 4)
        for index in range(1, count): record[index * 512 - 2:index * 512] = record[offset + index * 2:offset + index * 2 + 2]
        return record

    def protect(record):
        offset, count = struct.unpack_from("<HH", record, 4)
        p16(record, offset, 0xA55A)
        for index in range(1, count):
            record[offset + index * 2:offset + index * 2 + 2] = record[index * 512 - 2:index * 512]
            p16(record, index * 512 - 2, 0xA55A)
        return record

    record = unprotect(66)
    first = struct.unpack_from("<H", record, 20)[0]
    sequence = struct.unpack_from("<H", record, 16)[0]
    attrs = []
    offset = first
    while struct.unpack_from("<I", record, offset)[0] != 0xFFFFFFFF:
        length = struct.unpack_from("<I", record, offset + 4)[0]
        attrs.append(bytearray(record[offset:offset + length]))
        offset += length
    data_attr = next(attr for attr in attrs if struct.unpack_from("<I", attr)[0] == 0x80)
    p16(data_attr, 14, 0)
    entries = bytearray()
    for attr in sorted(attrs, key=lambda a: struct.unpack_from("<I", a)[0]):
        kind = struct.unpack_from("<I", attr)[0]
        entry = bytearray(32)
        p32(entry, 0, kind)
        p16(entry, 4, 32)
        p64(entry, 16, (12 | (9 << 48)) if kind == 0x80 else (66 | (sequence << 48)))
        p16(entry, 24, 0 if kind == 0x80 else struct.unpack_from("<H", attr, 14)[0])
        entries.extend(entry)
    attribute_list = bytearray(24 + len(entries))
    p32(attribute_list, 0, 0x20)
    p32(attribute_list, 4, len(attribute_list))
    p16(attribute_list, 14, 10)
    p32(attribute_list, 16, len(entries))
    p16(attribute_list, 20, 24)
    attribute_list[24:] = entries
    attrs = [attr for attr in attrs if struct.unpack_from("<I", attr)[0] != 0x80] + [attribute_list]
    attrs.sort(key=lambda a: struct.unpack_from("<I", a)[0])
    record[first:] = bytes(1024 - first)
    offset = first
    for attr in attrs:
        record[offset:offset + len(attr)] = attr
        offset += len(attr)
    p32(record, offset, 0xFFFFFFFF)
    p32(record, 24, offset + 8)
    p16(record, 40, 11)
    image[16384 + 66 * 1024:16384 + 67 * 1024] = protect(record)
    extension = bytearray(1024)
    extension[:4] = b"FILE"
    for offset, value in [(4, 48), (6, 3), (16, 9), (20, 56), (22, 1), (40, 1)]: p16(extension, offset, value)
    p32(extension, 24, 56 + len(data_attr) + 8)
    p32(extension, 28, 1024)
    p64(extension, 32, 66 | (sequence << 48))
    p32(extension, 44, 12)
    extension[56:56 + len(data_attr)] = data_attr
    p32(extension, 56 + len(data_attr), 0xFFFFFFFF)
    image[16384 + 12 * 1024:16384 + 13 * 1024] = protect(extension)
    # This fixture's $MFT bitmap has its one-cluster run at LCN 2.
    image[2 * 4096 + 12 // 8] |= 1 << (12 % 8)
    return bytes(image)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--libewf", type=Path)
    args = parser.parse_args()
    for name, data in [("fat16.raw", fat(16)), ("fat32.raw", fat(32)), ("ntfs-mbr.raw", ntfs_disk(False)), ("ntfs-gpt.raw", ntfs_disk(True)), ("ext2-indirect.raw", ext2_indirect()), ("ext4-extent.raw", ext4_extent()), ("ntfs-attrlist.raw", ntfs_attribute_list())]:
        (OUT / (name + ".gz")).write_bytes(gzip.compress(data, mtime=0))
        print(name, len(data), hashlib.sha256(data).hexdigest())
        if args.libewf and name in ("ntfs-mbr.raw", "ntfs-gpt.raw"):
            from validate_libewf import Libewf
            library = Libewf(args.libewf)
            base = OUT / name.removesuffix(".raw")
            if base.with_suffix(".E01").exists(): raise FileExistsError(base)
            library.write(base, data, 6, 2)


if __name__ == "__main__": main()
