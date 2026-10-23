"""Print `true` when silver_crypto_simd's locked dependencies differ between
two Cargo.lock files, else `false`.

Usage: crypto_simd_deps_changed.py BASE_LOCK HEAD_LOCK

Tests: python3 -m unittest discover -s .github/scripts -p crypto_simd_deps_changed.py

The dependencies are every package reachable from silver_crypto_simd. Each
resolved entry is compared whole, so a changed version, checksum or git
revision counts. Cargo.lock does not mark dev-dependencies, so they count too.
Exclude silver_crypto_simd's own entry: its version follows workspace
releases, and the caller checks `crates/crypto_simd` by path. Compare path
dependencies by their lockfile entries without reading their sources.
An edge that matches no entry, or more than one, also prints `true`: an
unparsed lockfile must never make the proof look irrelevant.
"""

import os
import re
import sys
import tempfile
import tomllib
import unittest

ROOT = "silver_crypto_simd"
# `name`, `name version` or `name version (source)`; the source omits any `#rev`.
EDGE = re.compile(r"(?P<name>\S+)(?: (?P<version>\S+))?(?: \((?P<source>[^)]+)\))?")


class Unresolved(Exception):
    pass


def resolve(edge, packages):
    m = EDGE.fullmatch(edge)
    if m is None:
        raise Unresolved(edge)
    found = [
        p
        for p in packages
        if p["name"] == m["name"]
        and (m["version"] is None or p["version"] == m["version"])
        and (m["source"] is None or p.get("source", "").split("#")[0] == m["source"])
    ]
    if len(found) != 1:
        raise Unresolved(edge)
    return found[0]


def dependencies(path):
    with open(path, "rb") as f:
        packages = tomllib.load(f).get("package", [])
    roots = [p for p in packages if p["name"] == ROOT]
    if len(roots) != 1:
        return None
    seen = {}
    todo = roots
    while todo:
        p = todo.pop()
        key = (p["name"], p["version"], p.get("source"))
        if key not in seen:
            seen[key] = p
            todo.extend(resolve(e, packages) for e in p.get("dependencies", []))
    return {key: p for key, p in seen.items() if p["name"] != ROOT}


def changed(base_path, head_path):
    try:
        base, head = dependencies(base_path), dependencies(head_path)
    except Unresolved as e:
        print(f"unresolved dependency edge: {e}", file=sys.stderr)
        return True
    return head is None or base != head


_REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
_GIT = "git+https://example.com/foo"


def _package(name, version, source=None, checksum=None, deps=()):
    lines = ["[[package]]", f'name = "{name}"', f'version = "{version}"']
    if source:
        lines.append(f'source = "{source}"')
    if checksum:
        lines.append(f'checksum = "{checksum}"')
    if deps:
        lines.append("dependencies = [" + ", ".join(f'"{d}"' for d in deps) + "]")
    return "\n".join(lines)


def _lock(*packages):
    return "version = 4\n\n" + "\n\n".join(packages) + "\n"


def _base_packages(
    blst_checksum="aa",
    rev="1111",
    unrelated="1.0.0",
    root_version="0.1.0",
    extra_deps=(),
):
    return [
        _package(
            ROOT,
            root_version,
            deps=["blst", f"foo 1.0.0 ({_GIT})", f"foo 1.0.0 ({_GIT}2)", *extra_deps],
        ),
        _package("blst", "0.3.16", _REGISTRY, blst_checksum, deps=["cc"]),
        _package("cc", "1.2.0", _REGISTRY, "cc"),
        _package("foo", "1.0.0", f"{_GIT}#{rev}"),
        _package("foo", "1.0.0", f"{_GIT}2#9999"),
        _package("tokio", unrelated, _REGISTRY, "dd"),
    ]


class TestChanged(unittest.TestCase):
    def check(self, base, head):
        with tempfile.TemporaryDirectory() as d:
            paths = []
            for name, text in (("base", base), ("head", head)):
                path = os.path.join(d, f"{name}.lock")
                with open(path, "w") as f:
                    f.write(text)
                paths.append(path)
            return changed(*paths)

    def test_identical_lockfiles_are_unchanged(self):
        self.assertFalse(self.check(_lock(*_base_packages()), _lock(*_base_packages())))

    def test_unrelated_package_is_ignored(self):
        head = _lock(*_base_packages(unrelated="1.1.0"))
        self.assertFalse(self.check(_lock(*_base_packages()), head))

    def test_registry_dependency_change_counts(self):
        head = _lock(*_base_packages(blst_checksum="bb"))
        self.assertTrue(self.check(_lock(*_base_packages()), head))

    def test_git_revision_of_source_qualified_dependency_counts(self):
        head = _lock(*_base_packages(rev="2222"))
        self.assertTrue(self.check(_lock(*_base_packages()), head))

    def test_root_version_is_ignored(self):
        head = _lock(*_base_packages(root_version="0.1.1"))
        self.assertFalse(self.check(_lock(*_base_packages()), head))

    def test_new_dependency_counts(self):
        head = _lock(*_base_packages(extra_deps=["tokio"]))
        self.assertTrue(self.check(_lock(*_base_packages()), head))

    def test_path_dependency_version_counts(self):
        def packages(version):
            return [
                *_base_packages(root_version=version, extra_deps=["silver_common"]),
                _package("silver_common", version),
            ]

        head = _lock(*packages("0.1.1"))
        self.assertTrue(self.check(_lock(*packages("0.1.0")), head))

    def test_transitive_dependency_change_counts(self):
        packages = _base_packages()
        packages[2] = _package("cc", "1.2.1", _REGISTRY, "cc")
        packages[1] = _package("blst", "0.3.16", _REGISTRY, "aa", deps=["cc"])
        self.assertTrue(self.check(_lock(*_base_packages()), _lock(*packages)))

    def test_unresolved_edge_counts(self):
        packages = _base_packages()
        packages[0] = _package(ROOT, "0.1.0", deps=["missing"])
        self.assertTrue(self.check(_lock(*packages), _lock(*packages)))

    def test_ambiguous_edge_counts(self):
        packages = _base_packages()
        packages[0] = _package(ROOT, "0.1.0", deps=["foo"])
        self.assertTrue(self.check(_lock(*packages), _lock(*packages)))

    def test_root_missing_at_base_counts(self):
        base = _lock(*_base_packages()[1:])
        self.assertTrue(self.check(base, _lock(*_base_packages())))


if __name__ == "__main__":
    print("true" if changed(sys.argv[1], sys.argv[2]) else "false")
