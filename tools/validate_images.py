"""Cross-check native image readers against TSK's independent libvmdk/libvhdi.

Run with --tsk target/tsk-oracle/sleuthkit-4.15.0-win32/bin/img_cat.exe.
No external libraries are linked into the Rust implementation or its tests.
"""
import argparse
import ctypes as c
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import struct

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/images"


class Vhdi:
    def __init__(self, path):
        self.lib = c.CDLL(str(path))
        p = c.c_void_p
        for name, args, result in [
            ("initialize", [c.POINTER(p)], c.c_int),
            ("open", [p, c.c_char_p, c.c_int], c.c_int),
            ("set_parent_file", [p, p], c.c_int),
            ("get_media_size", [p, c.POINTER(c.c_uint64)], c.c_int),
            ("read_buffer_at_offset", [p, p, c.c_size_t, c.c_int64], c.c_ssize_t),
            ("close", [p], c.c_int),
            ("free", [c.POINTER(p)], c.c_int),
        ]:
            fn = getattr(self.lib, "libvhdi_file_" + name)
            fn.argtypes = args + [c.POINTER(p)]
            fn.restype = result

    def call(self, name, *args):
        error = c.c_void_p()
        result = getattr(self.lib, "libvhdi_file_" + name)(*args, c.byref(error))
        if result < 0:
            message = c.create_string_buffer(4096)
            self.lib.libvhdi_error_backtrace_sprint(error, message, len(message))
            raise RuntimeError(message.value.decode(errors="replace"))
        return result

    def read(self, path, parent):
        handles = []
        for name in [parent, path]:
            handle = c.c_void_p()
            self.call("initialize", c.byref(handle))
            self.call("open", handle, str(name).encode(), 1)
            handles.append(handle)
        self.call("set_parent_file", handles[1], handles[0])
        size = c.c_uint64()
        self.call("get_media_size", handles[1], c.byref(size))
        data = c.create_string_buffer(size.value)
        assert self.call("read_buffer_at_offset", handles[1], data, size.value, 0) == size.value
        for handle in reversed(handles):
            self.call("close", handle)
            self.call("free", c.byref(handle))
        return data.raw


def difference_reference(path, parent_data):
    """VHD specification sector-bitmap overlay, independent of the Rust code.

    Older libvhdi reads allocated differential blocks without honoring individual
    bitmap bits. Check its child sectors separately; use the specified overlay
    for inherited sectors.
    """
    data = path.read_bytes()
    header = data[512:1536]
    table = struct.unpack_from(">Q", header, 16)[0]
    count, block = struct.unpack_from(">II", header, 28)
    bitmap = ((block // 512 + 7) // 8 + 511) // 512 * 512
    output = bytearray(parent_data)
    changed = []
    for i in range(count):
        location = struct.unpack_from(">I", data, table + i * 4)[0]
        if location == 0xffffffff:
            continue
        start = location * 512
        for sector in range(block // 512):
            at = i * block + sector * 512
            if at >= len(output):
                break
            if data[start + sector // 8] & (0x80 >> (sector % 8)):
                physical = start + bitmap + sector * 512
                output[at:at + 512] = data[physical:physical + 512]
                changed.append(at)
    return bytes(output), changed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tsk", type=Path, required=True)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/debug/inodex.exe")
    parser.add_argument("--vhdi", type=Path, required=True)
    args = parser.parse_args()
    work = ROOT / "target/image-corpus"
    work.mkdir(exist_ok=True)
    sources = json.loads((FIXTURES / "dfvfs-sources.json").read_text())
    for source in sources:
        data = gzip.decompress((FIXTURES / (source["name"] + ".gz")).read_bytes())
        assert hashlib.sha256(data).hexdigest() == source["sha256"]
        (work / source["name"]).write_bytes(data)
    results = {}
    for source in sources:
        name = source["name"]
        if name.endswith(".001"):
            continue
        path = work / name
        kind = "vhd" if name.endswith(".vhd") else "vmdk" if name.endswith(".vmdk") else "raw"
        if name in ["image.vhd", "image-differential.vhd"]:
            # Deliberately damaged public fixture: both footer copies fail their checksum.
            rust = subprocess.run([str(args.binary.resolve()), "info", str(path)], capture_output=True)
            assert rust.returncode and b"checksum mismatch" in rust.stderr
            print(name, "PASS (bad checksum rejected)")
            continue
        if "differential" in name:
            parent = "fat-parent.vhd" if name.startswith("fat-") else "ntfs-parent.vhd" if name.startswith("ntfs-") else "image.vhd"
            child = Vhdi(args.vhdi).read(path, work / parent)
            base = subprocess.run([str(args.tsk.resolve()), "-i", "vhd", str(work / parent)], capture_output=True, check=True).stdout
            data, changed = difference_reference(path, base)
            assert changed
            for at in changed:
                assert data[at:at + 512] == child[at:at + 512]
            oracle = subprocess.CompletedProcess([], 0, data, b"")
        else:
            oracle = subprocess.run([str(args.tsk.resolve()), "-i", kind, str(path)], capture_output=True)
        if oracle.returncode:
            raise RuntimeError(f"{name}: oracle failed: {oracle.stderr.decode(errors='replace')}")
        output = work / (name + ".rust.raw")
        output.unlink(missing_ok=True)
        rust = subprocess.run([str(args.binary.resolve()), "export", str(path), str(output)], capture_output=True)
        if rust.returncode:
            raise RuntimeError(f"{name}: Rust export failed: {rust.stderr.decode(errors='replace')}")
        assert output.read_bytes() == oracle.stdout, name
        results[name] = {"bytes": len(oracle.stdout), "sha256": hashlib.sha256(oracle.stdout).hexdigest()}
        (FIXTURES / (name + ".decoded.gz")).write_bytes(gzip.compress(oracle.stdout, mtime=0))
        print(name, "PASS", results[name])
    (FIXTURES / "tsk-image-reference.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
