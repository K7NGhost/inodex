"""Python 2/3-compatible oracle executed by an independent pytsk3 runtime.

Run via validate_tsk.py when using Autopsy's bundled Python 2 runtime.
"""
try:
    import hashlib
except ImportError:
    import _hashlib as hashlib
    hashlib.sha256 = hashlib.openssl_sha256
import pytsk3
import _codecs


def text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return _codecs.utf_8_decode(value, "replace", True)[0]
    return value


def file_kind(meta):
    if int(meta.type) == pytsk3.TSK_FS_META_TYPE_DIR:
        return "directory"
    if int(meta.type) == pytsk3.TSK_FS_META_TYPE_REG:
        return "file"
    if int(meta.type) == pytsk3.TSK_FS_META_TYPE_LNK:
        return "symlink"
    return "other"


def scan_filesystem(path, offset=0):
    image = pytsk3.Img_Info(path)
    fs = pytsk3.FS_Info(image, offset=offset)
    entries = []
    visited = set()

    def visit(inode, parent):
        if inode in visited:
            return
        visited.add(inode)
        for item in fs.open_dir(inode=inode):
            name = text(item.info.name.name)
            if name in (".", "..", "$OrphanFiles") or item.info.meta is None:
                continue
            if not int(item.info.name.flags) & pytsk3.TSK_FS_NAME_FLAG_ALLOC:
                continue
            meta = item.info.meta
            item_path = parent + "/" + name
            kind = file_kind(meta)
            record = {"path": item_path, "id": meta.addr, "kind": kind,
                      "size": meta.size, "allocated": bool(int(meta.flags) & pytsk3.TSK_FS_META_FLAG_ALLOC),
                      "modified": meta.mtime, "accessed": meta.atime,
                      "changed": meta.ctime, "created": meta.crtime, "streams": []}
            if kind in ("file", "symlink"):
                streams = []
                if int(fs.info.ftype) == pytsk3.TSK_FS_TYPE_NTFS:
                    for attribute in item:
                        if int(attribute.info.type) == pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA:
                            streams.append((text(attribute.info.name), attribute.info.size, int(attribute.info.type), attribute.info.id))
                else:
                    streams = [("", meta.size, None, None)]
                for stream_name, size, attr_type, attr_id in streams:
                    if size > 8 * 1024 * 1024:
                        samples = []
                        for offset in (0, 11 * 1024 + 1000, 12 * 1024, 267 * 1024 + 1017, 268 * 1024, 65803 * 1024 + 1000, 65804 * 1024, size - 2):
                            amount = min(1027, size - offset)
                            if attr_type is None:
                                data = item.read_random(offset, amount)
                            else:
                                data = item.read_random(offset, amount, attr_type, attr_id)
                            if len(data) != amount: raise ValueError("short oracle sample read")
                            samples.append({"offset": offset, "length": amount, "sha256": hashlib.sha256(data).hexdigest()})
                        record["streams"].append({"name": stream_name, "size": size, "samples": samples})
                        continue
                    digest = hashlib.sha256()
                    offset = 0
                    error = None
                    if kind == "symlink" and getattr(meta, "link", None):
                        target = meta.link
                        digest.update(target)
                        offset = len(target)
                    while offset < size:
                        count = min(65536, size - offset)
                        if attr_type is None:
                            data = item.read_random(offset, count)
                        else:
                            data = item.read_random(offset, count, attr_type, attr_id)
                        if not data:
                            error = "independent TSK returned a short read"
                            break
                        digest.update(data)
                        offset += len(data)
                    stream_record = {"name": stream_name, "size": size}
                    if error:
                        stream_record["oracle_error"] = error
                    else:
                        stream_record["sha256"] = digest.hexdigest()
                    record["streams"].append(stream_record)
            entries.append(record)
            if kind == "directory":
                visit(meta.addr, item_path)
    visit(fs.info.root_inum, "")
    return {"root_id": fs.info.root_inum, "block_size": fs.info.block_size,
            "entries": sorted(entries, key=lambda item: item["path"])}


def run(inputs, destination):
    result = {"pytsk3_version": text(pytsk3.get_version()), "filesystems": {}, "partitions": {}}
    for name, path in inputs.items():
        if name in ("exfat.raw", "ntfs.raw", "ntfs-attrlist.raw", "fat12.raw", "fat16.raw", "fat32.raw", "ext2.raw", "ext4.raw", "ext2-indirect.raw", "ext4-extent.raw"):
            result["filesystems"][name] = scan_filesystem(path)
        else:
            volume = pytsk3.Volume_Info(pytsk3.Img_Info(path))
            result["partitions"][name] = [{"start": part.start, "sectors": part.len, "description": text(part.desc), "flags": int(part.flags)} for part in volume]
            if name in ("ntfs-mbr.raw", "ntfs-gpt.raw"):
                result["filesystems"][name] = scan_filesystem(path, 2048 * 512)
    with open(destination, "w") as output:
        output.write(repr(result))


if __name__ == "__main__":
    import sys
    import json
    with open(sys.argv[1]) as config:
        values = json.load(config)
    run(values["inputs"], values["destination"])
