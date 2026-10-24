"""Run the independent TSK oracle using Autopsy's bundled pytsk3/Python runtime.

python tools/validate_tsk.py --runtime D:/Projects/autopsy/thirdparty/plaso/plaso-20180818-amd64
The Rust implementation and ordinary tests have no dependency on this runtime.
"""
import argparse
import ast
import ctypes as c
import gzip
import json
import os
import subprocess
import sys
import io
import tokenize
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--embedded-config", type=Path)
    args = parser.parse_args()
    runtime = args.runtime.resolve()
    if args.embedded_config:
        config = json.loads(args.embedded_config.read_text())
        execute_embedded(runtime, config["inputs"], config["destination"])
        return
    with tempfile.TemporaryDirectory(prefix="inodex-tsk-") as directory:
        inputs = {}
        modern_names=set(json.loads((ROOT / "tests/fixtures/layers/tsk-more-reference.json").read_text())["filesystems"])
        for source in [ROOT / "tests/fixtures/ext2.raw.gz"] + sorted((ROOT / "tests/fixtures/layers").glob("*.raw.gz")):
            if source.name.removesuffix(".raw.gz") in modern_names:
                continue  # These use the current CLI oracle in validate_more_tsk.py.
            dest = Path(directory) / source.stem
            dest.write_bytes(gzip.decompress(source.read_bytes()))
            inputs[dest.name] = str(dest)
        output = ROOT / "tests/fixtures/layers/tsk-reference.json"
        config = Path(directory) / "config.json"
        config.write_text(json.dumps({"inputs": inputs, "destination": str(output)}), encoding="utf-8")
        subprocess.run([sys.executable, __file__, "--runtime", str(runtime), "--embedded-config", str(config)], check=True)
        tokens = []
        previous = None
        for token in tokenize.generate_tokens(io.StringIO(output.read_text()).readline):
            if token.type == tokenize.NAME and token.string == "L" and previous and previous.type == tokenize.NUMBER and previous.end == token.start:
                continue
            tokens.append(token)
            previous = token
        reference = ast.literal_eval(tokenize.untokenize(tokens))
        output.write_text(json.dumps(reference, indent=2, sort_keys=True), encoding="utf-8")
        print("pytsk3", reference["pytsk3_version"])
        for name, fs in reference["filesystems"].items():
            print(name, len(fs["entries"]), "entries")
        print("Wrote", output)


def execute_embedded(runtime, inputs, output):
    dll_directory = os.add_dll_directory(str(runtime))
    python = c.CDLL(str(runtime / "python27.dll"))
    c.c_int.in_dll(python, "Py_NoSiteFlag").value = 1
    python.Py_SetPythonHome.argtypes = [c.c_char_p]
    runtime_buffer = c.create_string_buffer(str(runtime).encode())
    python.Py_SetPythonHome(runtime_buffer)
    python.Py_Initialize()
    python.PyRun_SimpleString.argtypes = [c.c_char_p]
    code = "import sys\nsys.path = [%r]\n__name__ = 'tsk_oracle'\nexecfile(%r)\nrun(%r, %r)\n" % (str(runtime), str(ROOT / "tools/tsk_oracle.py"), inputs, str(output))
    result = python.PyRun_SimpleString(code.encode())
    # Exit the isolated helper so all handles owned by old extension modules
    # close before the parent removes its temporary input files.
    python.PyRun_SimpleString(b"import sys; sys.stdout.flush(); sys.stderr.flush()")
    _ = dll_directory
    os._exit(0 if result == 0 else 1)


if __name__ == "__main__":
    main()
