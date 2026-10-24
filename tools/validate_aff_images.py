"""Generate and cross-check AFF/AFD/AFM fixtures with AFFLIB 3.7.20 tools.

The independent tools are development dependencies only. See fixture README
for source checksum and the Windows pointer-width build adjustment.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--afflib-bin", type=Path, required=True)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/debug/inodex.exe")
    parser.add_argument("--stream-oracle", type=Path, required=True)
    args = parser.parse_args()
    work = ROOT / "target/aff-generated"
    work.mkdir(exist_ok=True)
    raw = gzip.decompress((ROOT / "tests/fixtures/ext2.raw.gz").read_bytes())
    source = work / "source.raw"
    source.write_bytes(raw)
    records = {}
    for name, options in [("native.aff", []), ("plain.aff", ["-x"]), ("lzma.aff", ["-L"]),
                          ("multi.afd", ["-M16k"]), ("native.afm", ["-M1m"])]:
        path = work / name
        if not path.exists():
            subprocess.run([str((args.afflib_bin / "affconvert.exe").resolve()), "-q", "-s4k", *options, "-o", str(path), str(source)], check=True)
        oracle = subprocess.run([str(args.stream_oracle.resolve()), str(path)], capture_output=True, check=True).stdout
        assert oracle == raw
        output = work / (name + ".rust.raw")
        output.unlink(missing_ok=True)
        subprocess.run([str(args.binary.resolve()), "export", str(path), str(output)], check=True)
        assert output.read_bytes() == raw
        members = sorted(path.rglob("*.aff")) if path.is_dir() else [path]
        if path.suffix == ".afm":
            members += sorted(work.glob("native.[0-9][0-9][0-9]"))
        for member in members:
            relative = member.relative_to(work)
            target = ROOT / "tests/fixtures/images" / (str(relative) + ".gz")
            target.parent.mkdir(parents=True, exist_ok=True)
            data = member.read_bytes()
            target.write_bytes(gzip.compress(data, mtime=0))
            records[relative.as_posix()] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        print(name, "PASS", hashlib.sha256(oracle).hexdigest())
    (ROOT / "tests/fixtures/images/afflib-generated.json").write_text(json.dumps(records, indent=2) + "\n")


if __name__ == "__main__":
    main()
