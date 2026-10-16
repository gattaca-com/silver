#!/usr/bin/env python3
"""Supply the external dictionary and keep nested setup literals cheap to elaborate."""

import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
source = path.read_text()
marker = "namespace silver_crypto_simd\n"
if source.count(marker) != 1:
    raise SystemExit("expected exactly one silver_crypto_simd namespace")
if "def kzg.verify.CellBatchVerifier.verify\n" not in source or "sorry" in source:
    raise SystemExit("missing verifier or sorry in generated functions")
# Separate scopes prevent KZG from binding an independent BLS dictionary.
source = source.replace(marker, marker + "\nsection BlsScope\n\nvariable [bls.BlsExternals]\n", 1)
first_kzg = source.index("def kzg.")
split_at = source.rfind("/--", 0, first_kzg)
if split_at < 0 or re.search(r"^(?:@\[[^\]]*\]\s*)*def bls\.", source[split_at:], re.M):
    raise SystemExit("expected all BLS definitions before the KZG definitions")
source = source[:split_at] + "end BlsScope\n\nsection KzgScope\n\nvariable [kzg.KzgExternals]\n\n" + source[split_at:]
end_marker = "end silver_crypto_simd"
if source.count(end_marker) != 1:
    raise SystemExit("expected exactly one silver_crypto_simd namespace end")
source = source.replace(end_marker, "end KzgScope\n\n" + end_marker)

# `full` is a keyword in the imported Lean environment. Quoting preserves its name.
source, full_count = re.subn(r"\bfull\b", "«full»", source)
if full_count != 6:
    raise SystemExit(f"expected six generated full identifiers, found {full_count}")

# Array.make's default simp proof traverses the nested literal. Every list length is structural.
ends = []
for match in re.finditer(r"Array.make \d+#usize\s*\[", source):
    depth, end = 1, match.end()
    while depth:
        if source[end] == "[":
            depth += 1
        elif source[end] == "]":
            depth -= 1
        end += 1
    ends.append(end)
for end in sorted(ends, reverse=True):
    source = source[:end] + " (by rfl)" + source[end:]

# Hoist all 64 rows without changing their terms, order, or the outer array's type.
decl = source.index("def kzg.trusted_setup.G1_MONOMIAL :")
start = source.rfind("/--", 0, decl)
end = source.index("\n/--", decl)
block = source[decl:end]
if len(re.findall(r"\bdef\b", block)) != 1:
    raise SystemExit("expected exactly one def in the G1 setup block")
rows, offset = [], 0
while True:
    row_start = block.find("Array.make 48#usize [", offset)
    if row_start < 0:
        break
    row_end = block.index("] (by rfl)", row_start) + len("] (by rfl)")
    rows.append((row_start, row_end, block[row_start:row_end]))
    offset = row_end
if len(rows) != 64:
    raise SystemExit(f"expected 64 G1 setup rows, found {len(rows)}")
names = [f"kzg.trusted_setup.G1_MONOMIAL_row_{i}" for i in range(64)]
hoisted = "\n".join(
    f"private def {name} : Array Std.U8 48#usize :=\n  {row}\n"
    for name, (_, _, row) in zip(names, rows, strict=True)
)
for name, (row_start, row_end, _) in reversed(list(zip(names, rows, strict=True))):
    block = block[:row_start] + name + block[row_end:]
source = source[:start] + hoisted + "\n" + source[start:decl] + block + source[end:]
path.write_text(source)
