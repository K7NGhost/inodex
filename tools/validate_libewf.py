"""Independent E01 writer/reader validation using an installed libewf library.

python tools/validate_libewf.py --library path/to/libewf.dll --generate
python tools/validate_libewf.py --library path/to/libewf.dll --binary target/debug/inodex.exe

libewf is used only by this optional development tool, never by Rust or its tests.
"""

import argparse
import ctypes as c
import gzip
import hashlib
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


class Libewf:
    def __init__(self, path):
        self.lib = c.CDLL(str(path))
        ptr = c.c_void_p
        error = c.POINTER(ptr)
        signatures = {
            "initialize": ([c.POINTER(ptr), error], c.c_int),
            "free": ([c.POINTER(ptr), error], c.c_int),
            "open": ([ptr, c.POINTER(c.c_char_p), c.c_int, c.c_int, error], c.c_int),
            "close": ([ptr, error], c.c_int),
            "set_format": ([ptr, c.c_uint8, error], c.c_int),
            "set_media_size": ([ptr, c.c_uint64, error], c.c_int),
            "set_bytes_per_sector": ([ptr, c.c_uint32, error], c.c_int),
            "set_sectors_per_chunk": ([ptr, c.c_uint32, error], c.c_int),
            "set_compression_values": ([ptr, c.c_int8, c.c_uint8, error], c.c_int),
            "set_md5_hash": ([ptr, ptr, c.c_size_t, error], c.c_int),
            "set_sha1_hash": ([ptr, ptr, c.c_size_t, error], c.c_int),
            "write_buffer": ([ptr, ptr, c.c_size_t, error], c.c_ssize_t),
            "write_finalize": ([ptr, error], c.c_ssize_t),
            "read_random": ([ptr, ptr, c.c_size_t, c.c_int64, error], c.c_ssize_t),
            "get_media_size": ([ptr, c.POINTER(c.c_uint64), error], c.c_int),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.lib, "libewf_handle_" + name)
            function.argtypes = args
            function.restype = result
        self.lib.libewf_get_version.restype = c.c_char_p

    def call(self, name, *args):
        error = c.c_void_p()
        result = getattr(self.lib, "libewf_handle_" + name)(*args, c.byref(error))
        if result < 0:
            message = c.create_string_buffer(4096)
            self.lib.libewf_error_backtrace_sprint(error, message, len(message))
            self.lib.libewf_error_free(c.byref(error))
            raise RuntimeError(f"{name}: {message.value.decode(errors='replace')}")
        return result

    def handle(self, paths, access):
        handle = c.c_void_p()
        self.call("initialize", c.byref(handle))
        encoded = (c.c_char_p * len(paths))(*(str(path).encode() for path in paths))
        self.call("open", handle, encoded, len(paths), access)
        return handle

    def finish(self, handle):
        self.call("close", handle)
        self.call("free", c.byref(handle))

    def write(self, basename, data, format_number, compression):
        handle = self.handle([basename], 2)
        try:
            self.call("set_format", handle, format_number)
            self.call("set_bytes_per_sector", handle, 512)
            self.call("set_sectors_per_chunk", handle, 64)
            self.call("set_media_size", handle, len(data))
            self.call("set_compression_values", handle, compression, 0)
            md5 = hashlib.md5(data).digest()
            sha1 = hashlib.sha1(data).digest()
            self.call("set_md5_hash", handle, c.c_char_p(md5), len(md5))
            self.call("set_sha1_hash", handle, c.c_char_p(sha1), len(sha1))
            assert self.call("write_buffer", handle, c.c_char_p(data), len(data)) == len(data)
            self.call("write_finalize", handle)
        finally:
            self.finish(handle)

    def read(self, paths):
        handle = self.handle(paths, 1)
        try:
            size = c.c_uint64()
            self.call("get_media_size", handle, c.byref(size))
            buffer = c.create_string_buffer(size.value)
            assert self.call("read_random", handle, buffer, size.value, 0) == size.value
            return buffer.raw
        finally:
            self.finish(handle)


def generate(library):
    data = bytearray()
    seed = 0x49732
    for index in range(4 * 32768 + 512):
        seed = (1664525 * seed + 1013904223) & 0xFFFFFFFF
        chunk = index // 32768
        data.append(0 if chunk == 1 else index % 251 if chunk == 2 else seed >> 24)
    data = bytes(data)
    (FIXTURES / "libewf.raw.gz").write_bytes(gzip.compress(data, mtime=0))
    for number, name in [(1, "encase1"), (2, "encase2"), (3, "encase3"), (4, "encase4"), (5, "encase5"), (6, "encase6"), (15, "ftk")]:
        for compression in [0, 2]:
            base = FIXTURES / f"libewf-{name}-c{compression}"
            if list(FIXTURES.glob(base.name + ".*")):
                raise FileExistsError(f"Refusing to overwrite {base}")
            library.write(base, data, number, compression)
            print("generated", base.name)
    print("raw SHA256", hashlib.sha256(data).hexdigest())


def validate(library, binary):
    count = 0
    with tempfile.TemporaryDirectory(prefix="inodex-libewf-") as directory:
        for first in sorted(FIXTURES.glob("*.E01")):
            paths = [first]
            second = first.with_suffix(".E02")
            if second.exists():
                paths.append(second)
            reference = library.read(paths)
            raw_name = "ext2.raw.gz" if first.name.startswith("ext2") else "libewf.raw.gz"
            expected = gzip.decompress((FIXTURES / raw_name).read_bytes())
            assert reference == expected, f"libewf disagrees with source raw image: {first}"
            output = Path(directory) / (first.name + ".raw")
            subprocess.run([str(binary), "export", str(first), str(output)], check=True, capture_output=True)
            assert output.read_bytes() == reference, f"Rust disagrees with libewf: {first}"
            print("PASS", first.name, len(reference), "MD5", hashlib.md5(reference).hexdigest())
            count += 1
    print(f"Validated {count} image sets against libewf and original raw data")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    library = Libewf(args.library)
    print("libewf", library.lib.libewf_get_version().decode())
    if args.generate:
        generate(library)
    if args.binary:
        validate(library, args.binary.resolve())
    if not args.generate and not args.binary:
        parser.error("supply --generate or --binary")


if __name__ == "__main__":
    main()
