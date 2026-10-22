#!/usr/bin/env python3
"""Check that extraction normalization cannot hide changes to the setup expression.

Deterministic extractor fixtures exercise extract.sh --check without rebuilding Rust.
The ordinary extract.sh --check remains the separate real-tool check.
"""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


LEAN = Path(__file__).resolve().parents[1]


def git_head(directory):
    directory.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(directory)], check=True)
    subprocess.run(
        ["git", "-C", str(directory), "-c", "user.name=Extraction control",
         "-c", "user.email=control@example.invalid", "-c", "commit.gpgsign=false",
         "-c", "core.hooksPath=/dev/null", "commit", "-q", "--allow-empty", "-m", "fixture"],
        check=True,
    )
    return subprocess.check_output(
        ["git", "-C", str(directory), "rev-parse", "HEAD"], text=True
    ).strip()


def executable(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!{sys.executable}\n" + body)
    path.chmod(0o755)


source = (LEAN / "LeanBlsSimd/Extracted/Funs.lean").read_text()
rows = re.findall(
    r"private def kzg.trusted_setup.G1_MONOMIAL_row_\d+ : Array Std.U8 48#usize :=\s*"
    r"(Array.make 48#usize \[.*?\] \(by rfl\))", source, re.S
)
assert len(rows) == 64 and rows[0] != rows[-1], "fixture needs 64 rows with observable order"
rows = [row.replace(" (by rfl)", "") for row in rows]
prefix = (
    "import LeanBlsSimd.Extracted.FunsExternal\nopen Aeneas.Std\nnamespace silver_crypto_simd\n"
    "/-- BLS fixture --/\n"
    "@[irreducible] def bls.fixture (full : Nat) : Nat :=\n"
    "  full + full + full + full + full + full + full\n"
    "/-- Source: 'fixture.rs', lines 1:0-2:0 --/\n"
    "def kzg.trusted_setup.G1_MONOMIAL : Array (Array Std.U8 48#usize) 64#usize :=\n"
)
table = "  Array.make 64#usize [\n" + ",\n".join(rows) + "]\n"
suffix = (
    "\n/-- following --/\ndef kzg.verify.CellBatchVerifier.verify\n  : Nat := 0\n"
    "/-- extender constructor --/\ndef kzg.cell_extender.CellExtender.new\n  : Nat := 0\n"
    "/-- extender compute --/\ndef kzg.cell_extender.CellExtender.compute\n  : Nat := 4096\n"
    "/-- extender default --/\n"
    "def kzg.cell_extender.CellExtender.Insts.CoreDefaultDefault.default\n  : Nat := 0\n"
    "end silver_crypto_simd\n"
)
direct = prefix + table + suffix
reversed_table = prefix + "  let table :=\n  " + table + (
    "  ⟨table.val.reverse, by simpa using table.property⟩\n" + suffix
)
undocumented = prefix + table + "\ndef undocumented : Nat := 17\n" + suffix

with tempfile.TemporaryDirectory(prefix="kzg-extraction-control-") as tmp:
    root = Path(tmp)
    project = root / "crate/proof/lean"
    project.mkdir(parents=True)
    for name in ["extract.sh", "prepare-extraction.py"]:
        shutil.copy2(LEAN / name, project / name)

    toolchain = root / "tools"
    aeneas_pin = git_head(toolchain)
    charon_pin = git_head(toolchain / "charon")
    (toolchain / "charon-pin").write_text(charon_pin + "\n")
    (toolchain / "charon/charon").mkdir()
    (toolchain / "charon/charon/Cargo.toml").write_text('version = "0.0.0"\n')
    (project / "lake-manifest.json").write_text(json.dumps({
        "packages": [{"name": "aeneas", "rev": aeneas_pin}]
    }))
    executable(toolchain / "bin/aeneas", f"""
import pathlib, sys
if sys.argv[1:] == ['-version']:
    print('Aeneas {aeneas_pin}')
else:
    dest = pathlib.Path(sys.argv[sys.argv.index('-dest') + 1]) / 'LeanBlsSimd/Extracted'
    dest.mkdir(parents=True)
    dest.joinpath('Types.lean').write_text('-- fixture types\\n')
    dest.joinpath('Funs.lean').write_bytes(pathlib.Path({str(root / 'raw.lean')!r}).read_bytes())
""")
    executable(toolchain / "charon/bin/charon", """
import pathlib, sys
if sys.argv[1:] == ['version']:
    print('0.0.0')
else:
    roots = [sys.argv[i + 1] for i, arg in enumerate(sys.argv) if arg == '--start-from']
    assert 'crate::kzg::cell_extender' in roots, 'missing cell extender extraction root'
    pathlib.Path(sys.argv[sys.argv.index('--dest-file') + 1]).write_text('fixture')
""")
    committed = project / "LeanBlsSimd/Extracted"
    committed.mkdir(parents=True)
    (committed / "Types.lean").write_text("-- fixture types\n")
    (committed / "Funs.lean").write_text(direct)
    subprocess.run([sys.executable, "-I", str(project / "prepare-extraction.py"),
                    str(committed / "Funs.lean")], check=True)
    snapshot = (committed / "Funs.lean").read_bytes()

    def check(name, raw, expected, diagnostic):
        (root / "raw.lean").write_text(raw)
        result = subprocess.run(
            [str(project / "extract.sh"), "--check"], text=True,
            env={**os.environ, "AENEAS_DIR": str(toolchain)}, capture_output=True,
            timeout=30,
        )
        output = result.stdout + result.stderr
        assert result.returncode == expected, f"{name}: exit {result.returncode}\n{output}"
        assert diagnostic in output, f"{name}: missing diagnostic\n{output}"
        assert (committed / "Funs.lean").read_bytes() == snapshot, "--check wrote committed output"
        print(f"{name}: extract.sh --check exited {expected}; {diagnostic}")

    check("unchanged expression", direct, 0, "No drift")
    check("source-span-only edit", direct.replace("lines 1:0-2:0", "lines 31:7-45:2"), 0, "No drift")
    check("reversed table", reversed_table, 1, "table.val.reverse")
    check("undocumented declaration", undocumented, 1, "expected exactly one def")
    check("BLS declaration after KZG", direct.replace(
        "/-- following --/", "/-- late BLS --/\ndef bls.late : Nat := 0\n/-- following --/"),
        1, "expected all BLS definitions before the KZG definitions")
    check("attribute-prefixed BLS declaration after KZG", direct.replace(
        "/-- following --/",
        "/-- late BLS --/\n@[global_simps, irreducible] def bls.late : Nat := 0\n/-- following --/"),
        1, "expected all BLS definitions before the KZG definitions")
    check("missing reserved identifier", direct.replace("full + full", "full + 1", 1),
        1, "expected eight generated full identifiers, found 7")
    check("extender body edit", direct.replace(": Nat := 4096", ": Nat := 4095"),
        1, ": Nat := 4095")
    for entry_point in [
        "kzg.verify.CellBatchVerifier.verify",
        "kzg.cell_extender.CellExtender.new",
        "kzg.cell_extender.CellExtender.compute",
        "kzg.cell_extender.CellExtender.Insts.CoreDefaultDefault.default",
    ]:
        declaration = f"def {entry_point}\n"
        diagnostic = f"expected exactly one generated entry point: {entry_point}"
        check(f"missing {entry_point}", direct.replace(declaration, f"def missing_{entry_point}\n"),
            1, diagnostic)
        check(f"duplicate {entry_point}", direct.replace(declaration, declaration + declaration),
            1, diagnostic)
