"""Construct a small exFAT edge image; validate separately with validate_tsk.py.

This fixture is specification-built, not output from a native exFAT formatter.
Expected logical payloads are independent of both the Rust and TSK readers.
"""
import gzip
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "tests/fixtures/layers"


def make(libewf=None):
    data = bytearray(4096 * 512)

    def put(offset, fmt, *values):
        struct.pack_into("<" + fmt, data, offset, *values)

    def cluster(c):
        return (64 + c - 2) * 512

    def fat(c, nxt):
        put(24 * 512 + c * 4, "I", nxt)

    def checksum(payload, bits, skip=()):
        value = 0
        mask = (1 << bits) - 1
        for i, byte in enumerate(payload):
            if i not in skip:
                value = (((value >> 1) | ((value & 1) << (bits - 1))) + byte) & mask
        return value

    upcase = list(range(256))
    for i in range(97, 123):
        upcase[i] -= 32
    upcase[0xe4] = 0xc4
    upcase = struct.pack("<259H", *upcase, 0xffff, 65279, 0xffff)
    data[:11] = b"\xeb\x76\x90EXFAT   "
    put(72, "QIIIIIIHHBBBBB", 4096, 24, 32, 64, 4032, 2, 12345,
        0x100, 0, 9, 0, 1, 0x80, 0xff)
    put(510, "H", 0xaa55)
    for i in range(1, 9):
        put(i * 512 + 508, "I", 0xaa550000)
    boot_sum = checksum(data[:11 * 512], 32, (106, 107, 112))
    for i in range(128):
        put(11 * 512 + i * 4, "I", boot_sum)
    data[12 * 512:24 * 512] = data[:12 * 512]
    fat(0, 0xfffffff8)
    fat(1, 0xffffffff)
    for c in range(2, 12):
        fat(c, 0xffffffff)
        data[cluster(3) + (c - 2) // 8] |= 1 << ((c - 2) % 8)
    fat(4, 5)
    fat(8, 11)
    data[cluster(4):cluster(4) + len(upcase)] = upcase
    root = cluster(2)
    data[root] = 0x81
    put(root + 20, "IQ", 3, 504)
    data[root + 32] = 0x82
    put(root + 36, "I", checksum(upcase, 32))
    put(root + 52, "IQ", 4, len(upcase))
    data[root + 64:root + 66] = bytes((0x83, 5))
    data[root + 66:root + 76] = "TESTS".encode("utf-16le")

    def entry(at, name, first, size, valid=None, contiguous=True, directory=False):
        encoded = name.encode("utf-16le")
        count = (len(encoded) + 29) // 30
        record = bytearray(64 + count * 32)
        record[0:2] = bytes((0x85, count + 1))
        struct.pack_into("<H", record, 4, 0x10 if directory else 0x20)
        # 2024-06-15 12:34:56, UTC+02; creation has 230ms extra precision.
        stamp = ((44 << 9 | 6 << 5 | 15) << 16) | (12 << 11 | 34 << 5 | 28)
        struct.pack_into("<III", record, 8, stamp, stamp, stamp)
        record[20:25] = bytes((23, 0, 0x88, 0x88, 0x88))
        record[32:36] = bytes((0xc0, 3 if contiguous and size else 1, 0, len(encoded) // 2))
        folded = name.translate(str.maketrans({**{chr(i): chr(i-32) for i in range(97,123)}, "ä": "Ä"}))
        struct.pack_into("<H", record, 36, checksum(folded.encode("utf-16le"), 16))
        struct.pack_into("<Q", record, 40, size if valid is None else valid)
        struct.pack_into("<IQ", record, 52, first, size)
        for i in range(count):
            record[64 + i * 32] = 0xc1
            chunk = encoded[i * 30:(i + 1) * 30]
            record[66 + i * 32:66 + i * 32 + len(chunk)] = chunk
        struct.pack_into("<H", record, 2, checksum(record, 16, (2, 3)))
        data[at:at + len(record)] = record
        return at + len(record)

    at = entry(root + 96, "Gräße.txt", 6, 900, valid=700)
    at = entry(at, "fragmented.bin", 8, 800, contiguous=False)
    at = entry(at, "subdir", 9, 512, directory=True)
    entry(at, "empty", 0, 0)
    entry(cluster(9), "child.txt", 10, 12)
    data[cluster(6):cluster(6) + 1024] = bytes(i % 251 for i in range(1024))
    payload = bytes((i * 7 + 13) % 256 for i in range(800))
    data[cluster(8):cluster(8) + 512] = payload[:512]
    data[cluster(11):cluster(11) + 288] = payload[512:]
    data[cluster(10):cluster(10) + 12] = b"hello exfat!"
    ROOT.joinpath("exfat.raw.gz").write_bytes(gzip.compress(data, mtime=0))
    digest = hashlib.sha256(data).hexdigest()
    ROOT.joinpath("EXFAT_SHA256SUMS").write_text(f"{digest}  exfat.raw\n", encoding="ascii")
    print("exfat.raw", len(data), digest)
    if libewf:
        from validate_libewf import Libewf
        base = ROOT / "exfat"
        if base.with_suffix(".E01").exists():
            raise FileExistsError(base)
        Libewf(Path(libewf)).write(base, bytes(data), 6, 2)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--libewf")
    make(parser.parse_args().libewf)
