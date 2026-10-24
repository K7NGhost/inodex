"""Generate VMDK variants with the independent QEMU 2.3.0 writer."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import struct

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--qemu", type=Path, required=True)
    args = parser.parse_args()
    fixtures = ROOT / "tests/fixtures/images"
    work = ROOT / "target/qemu-generated"
    work.mkdir(exist_ok=True)
    raw = gzip.decompress((ROOT / "tests/fixtures/ext2.raw.gz").read_bytes())
    source = work / "source.raw"
    source.write_bytes(raw)
    records = {}
    for variant in ["monolithicSparse", "streamOptimized", "twoGbMaxExtentSparse", "monolithicFlat", "twoGbMaxExtentFlat"]:
        path = work / (variant + ".vmdk")
        subprocess.run([str(args.qemu.resolve()), "convert", "-f", "raw", "-O", "vmdk", "-o", "subformat=" + variant, str(source), str(path)], check=True)
        out = work / (variant + ".decoded")
        subprocess.run([str(args.qemu.resolve()), "convert", "-f", "vmdk", "-O", "raw", str(path), str(out)], check=True)
        assert out.read_bytes() == raw
        for member in work.glob(variant + "*.vmdk"):
            data = member.read_bytes()
            (fixtures / (member.name + ".gz")).write_bytes(gzip.compress(data, mtime=0))
            records[member.name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                                    "decoded_sha256": hashlib.sha256(raw).hexdigest()}
    # Convert QEMU's seekable stream output into the specified GD_AT_END framing.
    # Retain the independent grains/index; add a header copy and EOS, then check
    # the resulting footer layout using an independent reader in validate_images.
    stream = bytearray((work / "streamOptimized.vmdk").read_bytes())
    footer = bytes(stream[:512])
    struct.pack_into("<Q", stream, 56, 0xffffffffffffffff)
    marker = bytearray(512)
    struct.pack_into("<I", marker, 12, 3)
    stream.extend(marker + footer + bytes(512))
    name = "streamFooter.vmdk"
    (fixtures / (name + ".gz")).write_bytes(gzip.compress(stream, mtime=0))
    (work / name).write_bytes(stream)
    records[name] = {"bytes": len(stream), "sha256": hashlib.sha256(stream).hexdigest(), "decoded_sha256": hashlib.sha256(raw).hexdigest()}
    (fixtures / "qemu-generated.json").write_text(json.dumps(records, indent=2) + "\n")


if __name__ == "__main__":
    main()
