#!/usr/bin/env python3
"""Check exact literal expansion and exercise extraction drift guards with fake tools.

Use --raw RAW_FUNS --prepared EXTRACTED_DIR to check a real extraction independently
of the normalizer. With no arguments, run deterministic fixtures without Rust/Lean.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


LEAN = Path(__file__).resolve().parents[1]
GLOBALS = ("kzg.trusted_setup.G1_MONOMIAL", "kzg.pairing_lines.PAIRING_LINES")
HELPER = re.compile(
    r"\bkzg\.(?:trusted_setup\.G1_MONOMIAL_row_\d+|"
    r"pairing_lines\.PAIRING_LINES_step_\d+(?:_lane_\d+)?)\b"
)
FILES = ("Types.lean", "Literals.lean", "Funs.lean")


def length_proofs(text):
    # Independent stack walk: each closing array bracket receives one proof.
    starts = {match.end() - 1 for match in re.finditer(r"Array.make \d+#usize\s*\[", text)}
    stack, output = [], []
    for i, char in enumerate(text):
        if char == "[":
            stack.append(i in starts)
        output.append(char)
        if char == "]":
            assert stack, "unbalanced brackets in fixture"
            if stack.pop():
                output.append(" (by rfl)")
    assert not stack, "unbalanced brackets in fixture"
    return "".join(output)


def declaration(text, name):
    matches = list(re.finditer(r"^def " + re.escape(name) + r"\s*:", text, re.M))
    assert len(matches) == 1, f"expected one outer declaration: {name}"
    start = text.rfind("/--", 0, matches[0].start())
    following = re.search(r"\n(?:/--|private def |end silver_crypto_simd)", text[matches[0].end():])
    assert following, f"missing declaration boundary: {name}"
    end = matches[0].end() + following.start()
    block = text[start:end]
    header, body = block.split(":=", 1)
    return header, body.strip()


def inferred_type(expression):
    """Independently check the small literal grammar and its explicit array types."""
    expression = expression.replace(" (by rfl)", "")
    tokens = re.findall(r"Array\.make|\d+#(?:usize|u8|u64)|[\[\],]|\S+", expression)
    cursor = 0

    def read():
        nonlocal cursor
        token = tokens[cursor]
        cursor += 1
        if token != "Array.make":
            assert re.fullmatch(r"\d+#(?:u8|u64)", token), f"unexpected literal token: {token}"
            return "Std.U8" if token.endswith("#u8") else "Std.U64"
        size = tokens[cursor]
        assert re.fullmatch(r"\d+#usize", size), "missing literal size"
        assert tokens[cursor + 1] == "[", "missing literal list"
        cursor += 2
        children = []
        while tokens[cursor] != "]":
            children.append(read())
            if tokens[cursor] == ",":
                cursor += 1
            else:
                assert tokens[cursor] == "]", "missing literal separator"
        cursor += 1
        assert len(children) == int(size.split("#")[0]), "incorrect literal size"
        assert len(set(children)) == 1, "nonuniform literal children"
        child = children[0]
        return f"Array {('(' + child + ')') if child.startswith('Array ') else child} {size}"

    result = read()
    assert cursor == len(tokens), "unexpected literal suffix"
    return result


def validate_hoisting(raw, prepared):
    """Expand all helpers, compare exact expressions/outer headers, check helper types."""
    literals = prepared["Literals.lean"]
    functions = prepared["Funs.lean"]
    matches = list(re.finditer(r"^private def (\S+) : (.*?) :=\n", literals, re.M))
    definitions = {}
    for match in matches:
        name = match[1]
        assert HELPER.fullmatch(name), f"unexpected helper: {name}"
        assert name not in definitions, f"duplicate helper: {name}"
        # Helpers are separated by a blank line; their body is a single Array.make term.
        end = literals.index("\n\n", match.end())
        definitions[name] = (match[2], literals[match.end():end].strip())
    used = set()

    def expand(expression, active=()):
        def replace(match):
            name = match[0]
            assert name in definitions, f"missing helper: {name}"
            assert name not in active, f"cyclic helper: {name}"
            used.add(name)
            return expand(definitions[name][1], active + (name,))
        return HELPER.sub(replace, expression)

    for name in GLOBALS:
        assert not re.search(r"^def " + re.escape(name) + r"\s*:", functions, re.M), "literal remained in Funs"
        raw_header, raw_body = declaration(length_proofs(raw), name)
        header, body = declaration(literals, name)
        # Only Source span numbers may vary in whole-file comparisons. Here they
        # are unchanged: moving the declaration must preserve its complete header.
        assert header == raw_header, f"outer type/comment/attribute changed: {name}"
        assert expand(body) == raw_body, f"expanded literal differs: {name}"
    assert used == definitions.keys(), "unused helper definitions"
    for name, (declared_type, body) in definitions.items():
        assert inferred_type(expand(body)) == declared_type, f"helper type differs: {name}"
    assert functions.count("import LeanBlsSimd.Extracted.Literals\n") == 1
    assert "variable [RuntimeFeatures] [bls.BlsExternals] [KzgExternals]" in functions
    print(f"exact literal expansion: {len(definitions)} helpers; values, order, shapes, types and outer headers match")


def git_head(directory):
    directory.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(directory)], check=True)
    subprocess.run(
        ["git", "-C", str(directory), "-c", "user.name=Extraction control",
         "-c", "user.email=control@example.invalid", "-c", "commit.gpgsign=false",
         "-c", "core.hooksPath=/dev/null", "commit", "-q", "--allow-empty", "-m", "fixture"],
        check=True,
    )
    return subprocess.check_output(["git", "-C", str(directory), "rev-parse", "HEAD"], text=True).strip()


def executable(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!{sys.executable}\n" + body)
    path.chmod(0o755)


def array(children):
    return f"Array.make {len(children)}#usize [\n" + ",\n".join(children) + "\n]"


def fixtures():
    # Distinct small dimensions/values check that the normalizer infers sizes;
    # mutation targets are derived from these terms rather than committed tables.
    rows = [array([f"{10 * row + i}#u8" for i in range(5)]) for row in range(3)]
    lanes = [[array([f"{100 * step + 10 * lane + i}#u64" for i in range(4)])
              for lane in range(2)] for step in range(3)]
    steps = [array(step) for step in lanes]
    prefix = (
        "import LeanBlsSimd.Extracted.Types\nimport LeanBlsSimd.Extracted.FunsExternal\n"
        "open Aeneas.Std\nnamespace silver_crypto_simd\n"
        "/-- BLS fixture --/\n@[irreducible] def bls.fixture (full : Nat) : Nat :=\n"
        "  full + full + full + full + full + full + full\n"
        "/-- Source: 'fixture.rs', lines 1:0-2:0 --/\n@[global_simps, irreducible]\n"
        "def kzg.trusted_setup.G1_MONOMIAL : Array (Array Std.U8 5#usize) 3#usize :=\n"
    )
    middle = (
        "\n/-- Source: 'fixture.rs', lines 3:0-9:0 --/\n@[global_simps, irreducible]\n"
        "def kzg.pairing_lines.PAIRING_LINES : bls.miller_lines.MillerLines :=\n"
    )
    suffix = (
        "\n/-- following --/\ndef kzg.verify.CellBatchVerifier.verify\n  : Nat := 0\n"
        "/-- extender constructor --/\ndef kzg.cell_extender.CellExtender.new\n  : Nat := 0\n"
        "/-- extender compute --/\ndef kzg.cell_extender.CellExtender.compute\n  : Nat := 4096\n"
        "/-- extender default --/\n"
        "def kzg.cell_extender.CellExtender.Insts.CoreDefaultDefault.default\n  : Nat := 0\n"
        "/-- interleaved BLS --/\n@[irreducible] def bls.late : Nat := 0\n"
        "/-- interleaved portable --/\ndef portable.late : Nat := 1\n"
        "end silver_crypto_simd\n"
    )
    direct = prefix + array(rows) + middle + array(steps) + suffix
    with tempfile.TemporaryDirectory(prefix="kzg-extraction-control-") as tmp:
        root = Path(tmp)
        project = root / "crate/proof/lean"
        project.mkdir(parents=True)
        for name in ["extract.sh", "prepare-extraction.py"]:
            shutil.copy2(LEAN / name, project / name)
        (project / "controls").mkdir()
        shutil.copy2(Path(__file__), project / "controls/extraction-check.py")
        shutil.copy2(LEAN / "controls/setup-literals-check.py", project / "controls/setup-literals-check.py")
        # Keep the real pre-check candidates: stubs would hide a Lean dependency.
        mutation_checks = ("sha", "decoder", "msm")
        for name in mutation_checks:
            relative = f"controls/{name}-mutation-check.py"
            shutil.copy2(LEAN / relative, project / relative)
        for relative in ("LeanBlsSimd/Spec/Sha256.lean",
                         "LeanBlsSimd/Portable/Decode/Ordinary.lean",
                         "LeanBlsSimd/Portable/G1/Scott.lean",
                         "LeanBlsSimd/Portable/Msm/Finish.lean"):
            target = project / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(LEAN / relative, target)
        path_without_lean = root / "path-without-lean"
        path_without_lean.mkdir()
        for command in ("bash", "dirname", "python3", "git", "awk", "tail", "sed", "head",
                        "mktemp", "rm", "cp", "mkdir"):
            resolved = shutil.which(command)
            assert resolved is not None, f"missing extraction tool: {command}"
            (path_without_lean / command).symlink_to(resolved)
        assert shutil.which("lake", path=str(path_without_lean)) is None
        assert shutil.which("lean", path=str(path_without_lean)) is None
        assert not (project / ".lake").exists(), "fixture must not have build artifacts"
        source_setup = project.parents[1] / "src/kzg/setup.rs"
        source_setup.parent.mkdir(parents=True)
        shutil.copy2(LEAN.parents[1] / "src/kzg/setup.rs", source_setup)
        lean_setup = project / "LeanBlsSimd/Kzg/SetupLiterals.lean"
        lean_setup.parent.mkdir(parents=True)
        shutil.copy2(LEAN / "LeanBlsSimd/Kzg/SetupLiterals.lean", lean_setup)
        toolchain = root / "tools"
        aeneas_pin = git_head(toolchain)
        charon_pin = git_head(toolchain / "charon")
        (toolchain / "charon-pin").write_text(charon_pin + "\n")
        extraction_env = {**os.environ, "AENEAS_DIR": str(toolchain), "PATH": str(path_without_lean)}
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
    dest.joinpath('Types.lean').write_bytes(pathlib.Path({str(root / 'types.lean')!r}).read_bytes())
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
        (root / "types.lean").write_text("-- fixture types\n")
        (committed / "Funs.lean").write_text(direct)
        subprocess.run([sys.executable, "-I", str(project / "prepare-extraction.py"),
                        str(committed / "Funs.lean")], check=True)
        snapshot = {name: (committed / name).read_text() for name in FILES}
        control = project / "controls/ExtractedLiterals.lean"
        write_lean_control(direct, control)
        control_snapshot = control.read_text()
        validate_hoisting(direct, snapshot)

        def check(name, raw, expected, diagnostic):
            (root / "raw.lean").write_text(raw)
            result = subprocess.run(
                [str(project / "extract.sh"), "--check"], text=True,
                env=extraction_env, capture_output=True, timeout=30,
            )
            output = result.stdout + result.stderr
            assert result.returncode == expected, f"{name}: exit {result.returncode}\n{output}"
            assert diagnostic in output, f"{name}: missing diagnostic\n{output}"
            assert all((committed / f).read_text() == snapshot[f] for f in FILES), "--check wrote committed output"
            assert control.read_text() == control_snapshot, "--check wrote the Lean control"
            print(f"{name}: extract.sh --check exited {expected}; {diagnostic}")

        # A source-only literal change must stop both modes before output replacement.
        original_setup = source_setup.read_text()
        word = re.search(r"0x[0-9a-fA-F]+", original_setup)
        assert word is not None
        source_setup.write_text(original_setup[:word.start()] + hex(int(word[0], 16) ^ 1) + original_setup[word.end():])
        (root / "raw.lean").write_text(direct)
        for args in (["--check"], []):
            result = subprocess.run([str(project / "extract.sh"), *args], text=True,
                                    env=extraction_env,
                                    capture_output=True, timeout=30)
            assert result.returncode != 0 and "G2 literal differs" in result.stderr, result.stdout + result.stderr
            assert all((committed / name).read_text() == value for name, value in snapshot.items())
            assert control.read_text() == control_snapshot
            print(f"mutated G2 literal {args}: rejected before any output replacement")
        source_setup.write_text(original_setup)
        # Both modes must work before Lean is installed or the project is built.
        for args in (["--check"], []):
            result = subprocess.run([str(project / "extract.sh"), *args], text=True,
                                    env=extraction_env, capture_output=True, timeout=30)
            assert result.returncode == 0 and "No drift" in result.stdout, result.stdout + result.stderr
            print(f"extraction without lake or build artifacts {args}: passed")

        # Reinserting any Lean-dependent pre-check must break the same environment.
        extract_path = project / "extract.sh"
        extract_source = extract_path.read_text()
        for name in mutation_checks:
            extract_path.write_text(extract_source.replace(
                'AENEAS_DIR=$(cd "$AENEAS_DIR" && pwd)',
                f'python3 -I "$lean_dir/controls/{name}-mutation-check.py"\n'
                'AENEAS_DIR=$(cd "$AENEAS_DIR" && pwd)'))
            assert extract_path.read_text() != extract_source, "missing pre-check insertion point"
            for args in (["--check"], []):
                result = subprocess.run([str(extract_path), *args], text=True,
                                        env=extraction_env, capture_output=True, timeout=30)
                assert result.returncode != 0 and "No such file or directory: 'lake'" in result.stderr, result.stdout + result.stderr
                assert all((committed / f).read_text() == snapshot[f] for f in FILES)
                assert control.read_text() == control_snapshot
                print(f"Lean-dependent {name} pre-check {args}: rejected without lake")
            extract_path.write_text(extract_source)
        check("unchanged/interleaved functions", direct, 0, "No drift")
        check("source-span-only edit in literals", direct.replace("lines 1:0-2:0", "lines 31:7-45:2"), 0, "No drift")
        check("source comment edit", direct.replace("fixture.rs", "other.rs"), 1, "other.rs")
        check("mutated lane", direct.replace(lanes[0][0], lanes[0][0].replace("0#u64", "9#u64", 1)), 1, "9#u64")
        check("lane order", direct.replace(steps[0], array(list(reversed(lanes[0])))), 1, "10#u64")
        check("step order", direct.replace(array(steps), array(list(reversed(steps)))), 1, "200#u64")
        check("row order", direct.replace(array(rows), array(list(reversed(rows)))), 1, "20#u8")
        check("wrapped table", direct.replace(array(rows), "let table := " + array(rows) + "\ntable"), 1, "expected a pure Array.make")
        check("undocumented declaration", direct.replace(middle, "\ndef undocumented : Nat := 17\n" + middle), 1, "expected exactly one def")
        check("missing reserved identifier", direct.replace("full + full", "full + 1", 1), 1, "expected eight generated full identifiers, found 7")
        check("extender body edit", direct.replace(": Nat := 4096", ": Nat := 4095"), 1, ": Nat := 4095")
        (root / "types.lean").write_text("-- changed fixture types\n")
        check("Types comparison", direct, 1, "changed fixture types")
        (root / "types.lean").write_text("-- fixture types\n")
        for entry_point in ["kzg.verify.CellBatchVerifier.verify", "kzg.cell_extender.CellExtender.new",
                            "kzg.cell_extender.CellExtender.compute", "kzg.cell_extender.CellExtender.Insts.CoreDefaultDefault.default"]:
            decl = f"def {entry_point}\n"
            diagnostic = f"expected exactly one generated entry point: {entry_point}"
            check(f"missing {entry_point}", direct.replace(decl, f"def missing_{entry_point}\n"), 1, diagnostic)
            check(f"duplicate {entry_point}", direct.replace(decl, decl + decl), 1, diagnostic)

        def rejects(name, mutation, diagnostic):
            changed = dict(snapshot)
            changed["Literals.lean"] = mutation(changed["Literals.lean"])
            try:
                validate_hoisting(direct, changed)
            except AssertionError as error:
                assert diagnostic in str(error), f"{name}: {error}"
                print(f"{name}: exact-expansion check rejected; {error}")
            else:
                raise AssertionError(f"{name}: corrupt literal accepted")

        rejects("corrupt lane", lambda s: s.replace("0#u64", "9#u64", 1), "expanded literal differs")
        rejects("corrupt step order", lambda s: s.replace(
            "[\nkzg.pairing_lines.PAIRING_LINES_step_0,", "[\nkzg.pairing_lines.PAIRING_LINES_step_1,", 1), "expanded literal differs")
        rejects("corrupt lane order", lambda s: s.replace(
            "[\nkzg.pairing_lines.PAIRING_LINES_step_0_lane_0,", "[\nkzg.pairing_lines.PAIRING_LINES_step_0_lane_1,", 1), "expanded literal differs")
        helper = "kzg.pairing_lines.PAIRING_LINES_step_0_lane_0"
        rejects("missing helper", lambda s: re.sub(
            r"private def " + re.escape(helper) + r" : .*?\n\n", "", s, count=1, flags=re.S), "missing helper")
        rejects("duplicate helper", lambda s: s.replace(
            f"private def {helper} :", f"private def {helper} : Array Std.U64 4#usize :=\n  " + lanes[0][0] +
            f" (by rfl)\n\nprivate def {helper} :", 1), "duplicate helper")
        rejects("corrupt helper type", lambda s: s.replace("Array Std.U64 4#usize :=", "Array Std.U8 4#usize :=", 1), "helper type differs")
        rejects("corrupt outer attribute", lambda s: s.replace("global_simps, irreducible", "irreducible", 1), "outer type/comment/attribute changed")

        # Even mutually matching prepared/committed corruption must fail against raw output.
        prepare_path = project / "prepare-extraction.py"
        prepare_source = prepare_path.read_text()
        prepare_path.write_text(prepare_source + "\np = Path(sys.argv[1]).with_name('Literals.lean')\n"
                                "p.write_text(p.read_text().replace('0#u64', '9#u64', 1))\n")
        (committed / "Literals.lean").write_text(snapshot["Literals.lean"].replace("0#u64", "9#u64", 1))
        corrupt_snapshot = {name: (committed / name).read_bytes() for name in FILES}
        (root / "raw.lean").write_text(direct)
        for args in (["--check"], []):
            result = subprocess.run([str(project / "extract.sh"), *args], text=True,
                                    env=extraction_env,
                                    capture_output=True, timeout=30)
            assert result.returncode != 0 and "expanded literal differs" in result.stderr, result.stdout + result.stderr
            assert all((committed / name).read_bytes() == value for name, value in corrupt_snapshot.items())
            assert control.read_text() == control_snapshot
            print(f"corrupt normalizer {args}: raw expansion rejected before any output replacement")
        prepare_path.write_text(prepare_source)
        (committed / "Literals.lean").write_text(snapshot["Literals.lean"])

        # Default mode must update every output after reporting their drift.
        changed_raw = direct.replace(": Nat := 4096", ": Nat := 4095").replace("0#u64", "9#u64", 1)
        (root / "raw.lean").write_text(changed_raw)
        (root / "types.lean").write_text("-- changed fixture types\n")
        result = subprocess.run([str(project / "extract.sh")], text=True,
                                env=extraction_env,
                                capture_output=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        updated = {name: (committed / name).read_text() for name in FILES}
        assert all(updated[name] != snapshot[name] for name in FILES), "default extraction did not copy every file"
        validate_hoisting(changed_raw, updated)
        assert updated["Types.lean"] == "-- changed fixture types\n"
        assert ": Nat := 4095" in updated["Funs.lean"]
        assert control.read_text() != control_snapshot, "default mode did not regenerate the Lean control"
        assert "9#u64" in control.read_text()
        print("default extraction: Types/Literals/Funs and the Lean control all replaced")


def write_lean_control(raw, path):
    """Generate small pointwise equalities; never elaborate either full raw table."""
    checks = ["import LeanBlsSimd.Extracted.Literals", "open Aeneas.Std",
              "namespace silver_crypto_simd", "",
              "-- Each equality elaborates one raw row or lane from the extraction."]
    counts = []
    for name, tag in zip(GLOBALS, ("u8", "u64")):
        _, body = declaration(length_proofs(raw), name)
        pattern = (r"Array\.make \d+#usize\s*\[\s*(?:\d+#" + tag +
                   r"\s*,\s*)*\d+#" + tag + r"\s*\] \(by rfl\)")
        leaves = re.findall(pattern, body)
        sizes = [int(size) for size in re.findall(r"Array.make (\d+)#usize", body)]
        if tag == "u8":
            assert len(leaves) == sizes[0]
            indices = [(i,) for i in range(len(leaves))]
        else:
            assert len(leaves) == sizes[0] * sizes[1]
            indices = [(i // sizes[1], i % sizes[1]) for i in range(len(leaves))]
        for indices, leaf in zip(indices, leaves):
            selected = name + "".join(f".val[{i}]!" for i in indices)
            checks.append(f"example : {selected} =\n  {leaf} := by\n  unfold {name}\n  rfl\n")
        counts.append(len(leaves))
    checks.append("end silver_crypto_simd\n")
    path.write_text("\n".join(checks))
    print(f"generated Lean pointwise equality control: {counts[0]} rows and {counts[1]} lanes: {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path)
    parser.add_argument("--prepared", type=Path)
    parser.add_argument("--lean-control", type=Path, help="write row/lane equality examples; requires --raw")
    args = parser.parse_args()
    if args.raw or args.prepared:
        if not (args.raw and args.prepared):
            parser.error("--raw and --prepared must be supplied together")
        validate_hoisting(args.raw.read_text(), {name: (args.prepared / name).read_text() for name in FILES})
        if args.lean_control:
            write_lean_control(args.raw.read_text(), args.lean_control)
    else:
        if args.lean_control:
            parser.error("--lean-control requires --raw and --prepared")
        fixtures()


if __name__ == "__main__":
    main()
