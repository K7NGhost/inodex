"""Fetch pinned, independently authored dfVFS disk containers (development only)."""
import gzip
import hashlib
import json
from pathlib import Path
import urllib.request

REF = "d365f334da42169276e2083a27f75bc2afa48ea8"
ROOT = Path(__file__).resolve().parents[1] / "tests/fixtures/images"


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    url = f"https://api.github.com/repos/log2timeline/dfvfs/git/trees/{REF}?recursive=1"
    tree = json.load(urllib.request.urlopen(url))["tree"]
    records = []
    for entry in tree:
        name = entry["path"].removeprefix("test_data/")
        if not entry["path"].startswith("test_data/") or not (
            name.endswith((".vhd", ".vmdk")) or name.startswith("ext2.splitraw.")
        ):
            continue
        source = f"https://raw.githubusercontent.com/log2timeline/dfvfs/{REF}/test_data/{name}"
        data = urllib.request.urlopen(source).read()
        assert hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == entry["sha"]
        (ROOT / (name + ".gz")).write_bytes(gzip.compress(data, mtime=0))
        records.append({"name": name, "source": source, "git_blob": entry["sha"],
                        "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        print(name, len(data))
    (ROOT / "dfvfs-sources.json").write_text(json.dumps(records, indent=2) + "\n")


if __name__ == "__main__":
    main()
