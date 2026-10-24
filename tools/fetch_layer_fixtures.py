"""Fetch pinned dfVFS partition/filesystem fixtures, verifying Git blob IDs."""
import gzip
import hashlib
from pathlib import Path
import urllib.request

REF = "d365f334da42169276e2083a27f75bc2afa48ea8"
ROOT = Path(__file__).resolve().parents[1] / "tests/fixtures/layers"
FILES = {
    "ntfs.raw": "29594d173b85c52560f4e0ced289fdb48bb4a136",
    "fat12.raw": "613c3fd6e39b2821a954b6d682e3bd3518de7b83",
    "ext4.raw": "f1fe4d4bf9352d9742dbc7611218c2bee5bb13b4",
    "mbr.raw": "e9613f80bad8d0d0911eac5664fbdc99848f64eb",
    "gpt.raw": "1b59eace8589083ba006bdceb77421552038bb9d",
    "gpt_empty.raw": "a96bb2fcd55d9ab953cf176709e82374dadeab87",
    "gpt_non_sequential.raw": "9f26e90c247750b8a8ebbd61455d713804180211",
}


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    hashes = []
    for name, expected in FILES.items():
        data = urllib.request.urlopen(f"https://raw.githubusercontent.com/log2timeline/dfvfs/{REF}/test_data/{name}", timeout=60).read()
        blob = b"blob " + str(len(data)).encode() + b"\0" + data
        if hashlib.sha1(blob).hexdigest() != expected:
            raise ValueError(f"Git blob mismatch: {name}")
        (ROOT / (name + ".gz")).write_bytes(gzip.compress(data, mtime=0))
        digest = hashlib.sha256(data).hexdigest()
        hashes.append(f"{digest}  {name}\n")
        print(name, len(data), digest)
    (ROOT / "RAW_SHA256SUMS").write_text("".join(hashes), encoding="utf-8")


if __name__ == "__main__":
    main()
