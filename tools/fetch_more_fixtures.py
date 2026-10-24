"""Fetch pinned, independently produced filesystem images from dfVFS."""
import gzip
import hashlib
from pathlib import Path
import urllib.request

REF = "d365f334da42169276e2083a27f75bc2afa48ea8"
ROOT = Path(__file__).resolve().parents[1] / "tests/fixtures/layers"
FILES = {
    "apfs.raw": "5587de8ba4aec9f2682b4997c08f2edc4961970b",
    "hfsplus.raw": "2be256cc33b7ac0894ac226e2c1416b05a826af9",
    "ufs1.raw": "a4634e21b4859dba3a24837771f5cf99a5d714b5",
    "ufs2.raw": "6b15a8c79a6f21fe758290e03fd3b3ecfd70667a",
    "iso9660.raw": "c4a3446960d8acd8f20370c0011064d42b0038a8",
}

def main():
    hashes = []
    for name, expected in FILES.items():
        data = urllib.request.urlopen(f"https://raw.githubusercontent.com/log2timeline/dfvfs/{REF}/test_data/{name}", timeout=60).read()
        assert hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == expected, name
        (ROOT / (name + ".gz")).write_bytes(gzip.compress(data, mtime=0))
        hashes.append(f"{hashlib.sha256(data).hexdigest()}  {name}\n")
        print(name, len(data))
    (ROOT / "MORE_RAW_SHA256SUMS").write_text("".join(hashes), encoding="ascii")

if __name__ == "__main__":
    main()
