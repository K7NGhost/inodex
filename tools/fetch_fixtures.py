"""Refresh pinned public dfVFS test fixtures; not needed to run the tests."""

import gzip
import hashlib
from pathlib import Path
import urllib.request

REF = "d365f334da42169276e2083a27f75bc2afa48ea8"
ROOT = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
HASHES = {
    "ext2.E01": "ab9ea9a4951b74c37025ba40a978e85b1e4a0d94438080afb636144170d3f35b",
    "ext2.split.E01": "d14f130c462b0ab8efb6bb44bbfe5680e00ffaa90538cde84579d1eb0dcac00f",
    "ext2.split.E02": "b508375954ec1d1caeed8a6e5fc503f98493816ad6a3af89f5d220244c5f2864",
    "ext2.raw": "a6c2f0e39afe6c6ab432ca5465349fcefe8dc944398e97b2d957d3f89dbb5d80",
    "LICENSE": "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
}


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    for name in ("ext2.E01", "ext2.split.E01", "ext2.split.E02", "ext2.raw", "LICENSE"):
        source = "LICENSE" if name == "LICENSE" else f"test_data/{name}"
        url = f"https://raw.githubusercontent.com/log2timeline/dfvfs/{REF}/{source}"
        data = urllib.request.urlopen(url, timeout=60).read()
        if hashlib.sha256(data).hexdigest() != HASHES[name]:
            raise ValueError(f"SHA256 mismatch for {name}")
        dest = ROOT / ("LICENSE.dfvfs" if name == "LICENSE" else name)
        if name.endswith(".raw"):
            dest = ROOT / (name + ".gz")
            dest.write_bytes(gzip.compress(data, mtime=0))
            print("raw MD5", hashlib.md5(data).hexdigest(), "SHA1", hashlib.sha1(data).hexdigest())
        else:
            dest.write_bytes(data)
        print(name, len(data), hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    main()
