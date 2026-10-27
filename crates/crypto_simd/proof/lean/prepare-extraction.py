#!/usr/bin/env python3
"""Bind runtime dictionaries and split configured nested literals into their own module."""

from dataclasses import dataclass
from pathlib import Path
import re
import sys


# Restrict hoisting to reviewed, pure setup globals. Sizes come from the extraction.
LITERALS = {
    "kzg.trusted_setup.G1_MONOMIAL": ("u8", ("row",)),
    "kzg.pairing_lines.PAIRING_LINES": ("u64", ("step", "lane")),
}
ENTRY_POINTS = (
    "kzg.verify.CellBatchVerifier.verify",
    "kzg.cell_extender.CellExtender.new",
    "kzg.cell_extender.CellExtender.compute",
    "kzg.cell_extender.CellExtender.Insts.CoreDefaultDefault.default",
)
NAMESPACE = "namespace silver_crypto_simd\n"
END_NAMESPACE = "end silver_crypto_simd"
ARRAY_START = re.compile(r"Array\.make (\d+)#usize\s*\[")
LEAF = re.compile(r"\d+#(u8|u64)\b")
WHITESPACE = re.compile(r"\s*")


@dataclass
class ArrayLiteral:
    start: int
    end: int
    length: int
    children: list
    lean_type: str


def parse_array(text, offset=0):
    """Read only Array.make trees with unsigned numeric leaves, not general Lean."""
    start = offset
    match = ARRAY_START.match(text, offset)
    if not match:
        raise ValueError("expected a pure Array.make literal")
    length = int(match[1])
    offset = match.end()
    children, child_types = [], []
    while True:
        offset = WHITESPACE.match(text, offset).end()
        if text[offset:offset + 1] == "]":
            offset += 1
            break
        if text.startswith("Array.make", offset):
            child = parse_array(text, offset)
            children.append(child)
            child_types.append(child.lean_type)
            offset = child.end
        else:
            leaf = LEAF.match(text, offset)
            if not leaf:
                raise ValueError("expected an unsigned literal or nested Array.make")
            children.append(text[offset:leaf.end()])
            child_types.append("Std.U8" if leaf[1] == "u8" else "Std.U64")
            offset = leaf.end()
        offset = WHITESPACE.match(text, offset).end()
        if text[offset:offset + 1] == ",":
            offset += 1
        elif text[offset:offset + 1] != "]":
            raise ValueError("expected a comma or end of array literal")
    proof = " (by rfl)"
    if not text.startswith(proof, offset):
        raise ValueError("expected structural Array.make length proof")
    offset += len(proof)
    if length != len(children) or not children:
        raise ValueError(f"literal length {length} differs from {len(children)} elements")
    if len(set(child_types)) != 1:
        raise ValueError("nonuniform nested array element types")
    element_type = child_types[0]
    if element_type.startswith("Array "):
        element_type = f"({element_type})"
    return ArrayLiteral(start, offset, length, children,
                        f"Array {element_type} {length}#usize")


def adapt_lengths(source):
    ends = []
    for match in re.finditer(r"Array.make \d+#usize\s*\[", source):
        depth, end = 1, match.end()
        while depth and end < len(source):
            if source[end] == "[":
                depth += 1
            elif source[end] == "]":
                depth -= 1
            end += 1
        if depth:
            raise ValueError("unterminated Array.make literal")
        if source.startswith(" (by rfl)", end):
            raise ValueError("extraction is already prepared")
        ends.append(end)
    for end in sorted(ends, reverse=True):
        source = source[:end] + " (by rfl)" + source[end:]
    return source


def literal_block(source, name):
    declarations = list(re.finditer(r"^def " + re.escape(name) + r"\s*:", source, re.M))
    if len(declarations) != 1:
        raise ValueError(f"expected exactly one generated literal: {name}")
    decl = declarations[0].start()
    start = source.rfind("/--", 0, decl)
    if start < 0:
        raise ValueError(f"expected documentation before {name}")
    end = source.find("\n/--", decl)
    if end < 0:
        end = source.index(END_NAMESPACE, decl)
    block = source[start:end]
    if len(re.findall(r"\bdef\b", source[decl:end])) != 1:
        raise ValueError(f"expected exactly one def in the {name} block")
    assignment = source.index(":=", decl, end) + 2
    body_start = assignment + len(source[assignment:end]) - len(source[assignment:end].lstrip())
    node = parse_array(source, body_start)
    if source[node.end:end].strip():
        raise ValueError(f"unexpected expression after {name} literal")
    return start, end, body_start, node


def hoist(source, name, leaf_tag, levels):
    start, end, body_start, root = literal_block(source, name)
    definitions = []

    def visit(node, path=()):
        if len(path) == len(levels) + 1:
            raise ValueError(f"unexpected nesting depth in {name}")
        array_children = [isinstance(child, ArrayLiteral) for child in node.children]
        if any(array_children) != all(array_children):
            raise ValueError(f"mixed scalar and array elements in {name}")
        if all(array_children):
            if len(path) == len(levels):
                raise ValueError(f"unexpected nesting depth in {name}")
            replacements = []
            for i, child in enumerate(node.children):
                child_path = path + (i,)
                child_name = name + "".join(
                    f"_{label}_{index}" for label, index in zip(levels, child_path)
                )
                body = visit(child, child_path)
                definitions.append(f"private def {child_name} : {child.lean_type} :=\n  {body}\n")
                replacements.append((child.start, child.end, child_name))
            body = source[node.start:node.end]
            for left, right, replacement in reversed(replacements):
                body = body[:left - node.start] + replacement + body[right - node.start:]
            return body
        if len(path) != len(levels) or any(
            not child.endswith("#" + leaf_tag) for child in node.children
        ):
            raise ValueError(f"unexpected scalar type or nesting depth in {name}")
        return source[node.start:node.end]

    body = visit(root)
    # The generated outer declaration, including its type, attributes and documentation,
    # moves intact; only its nested array terms become references.
    outer = source[start:body_start] + body + source[root.end:end]
    return source[:start] + source[end:], "\n".join(definitions) + "\n" + outer


def prepare(source):
    if source.count(NAMESPACE) != 1 or source.count(END_NAMESPACE) != 1:
        raise ValueError("expected exactly one silver_crypto_simd namespace")
    for entry_point in ENTRY_POINTS:
        if source.count(f"def {entry_point}\n") != 1:
            raise ValueError(f"expected exactly one generated entry point: {entry_point}")
    if "sorry" in source:
        raise ValueError("sorry in generated functions")
    source, full_count = re.subn(r"\bfull\b", "«full»", source)
    if full_count != 8:
        raise ValueError(f"expected eight generated full identifiers, found {full_count}")
    source = adapt_lengths(source)
    header = source[:source.index(NAMESPACE)]
    header = header.replace("-- [silver_crypto_simd]: function definitions",
                            "-- [silver_crypto_simd]: hoisted setup literals")
    header = header.replace("import LeanBlsSimd.Extracted.FunsExternal\n", "")
    blocks = []
    for name, (leaf_tag, levels) in LITERALS.items():
        source, block = hoist(source, name, leaf_tag, levels)
        blocks.append(block)
    literals = header + NAMESPACE + "\n" + "\n".join(blocks) + "\n" + END_NAMESPACE + "\n"
    source = source.replace("import LeanBlsSimd.Extracted.FunsExternal\n",
                            "import LeanBlsSimd.Extracted.FunsExternal\n"
                            "import LeanBlsSimd.Extracted.Literals\n", 1)
    # Portable and SIMD functions interleave in the extraction. Lean only binds
    # a section variable when the generated definition actually uses it.
    source = source.replace(NAMESPACE, NAMESPACE + "\nsection RuntimeScope\n\n"
                            "variable [RuntimeFeatures] [bls.BlsExternals] [KzgExternals]\n", 1)
    source = source.replace(END_NAMESPACE, "end RuntimeScope\n\n" + END_NAMESPACE, 1)
    return source, literals


def main():
    path = Path(sys.argv[1])
    try:
        functions, literals = prepare(path.read_text())
    except ValueError as error:
        raise SystemExit(str(error)) from error
    path.with_name("Literals.lean").write_text(literals)
    path.write_text(functions)


if __name__ == "__main__":
    main()
