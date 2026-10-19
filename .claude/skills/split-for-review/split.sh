#!/usr/bin/env bash
# Mechanical parts of the split-for-review skill. Index-only: this script never
# writes to a tracked file in the worktree.
set -euo pipefail

repo=$(git rev-parse --show-toplevel)
cd "$repo"
work="${SPLIT_WORK:-${TMPDIR:-/tmp}/split-for-review/$(basename "$repo")}"
snap="$work/snapshot"
idx="$work/idx"
meta="$work/meta"
mkdir -p "$work"

die() { echo "split.sh: $*" >&2; exit 1; }

# Repo policy, kept in one place: fixture dirs to link into the extract, and the
# lint allowances the repo's own clippy recipe applies.
FIXTURE_RE='consensus-spec-tests|fixtures|test-vectors'
CHECK_CLIPPY_ALLOW='-A clippy::collapsible_if'

# SPLIT_EXCLUDE: extended regex of paths that are not part of the change
# (e.g. an untracked scratch directory).
changed_files() {
  { git diff --name-only
    git diff --cached --name-only
    git ls-files --others --exclude-standard
  } | sort -u | { if [ -n "${SPLIT_EXCLUDE:-}" ]; then grep -Ev "$SPLIT_EXCLUDE" || true; else cat; fi; }
}

# A tree as a standalone one-commit repository: build scripts that read
# version-control metadata do not compile in a bare extract. The extract
# persists and only files that differ are rewritten, because cargo rebuilds
# every crate whose sources have a newer mtime than its last build.
sync_tree() {
  ( cd "$1" && export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null &&
    { git update-index -q --refresh > /dev/null || true; } &&
    git read-tree --reset -u "$2" && git clean -fdq &&
    git update-ref HEAD "$(git -c user.name=split -c user.email=split@local commit-tree "$2" -m index)" )
}

init_extract() {
  rm -rf "$1"; mkdir -p "$1"
  git -C "$1" init -q
  echo "$(git rev-parse --path-format=absolute --git-common-dir)/objects" > "$1/.git/objects/info/alternates"
}

extract_tree() {
  [ -d "$1/.git" ] || init_extract "$1"
  # A failed sync (objects pruned by gc, a build script wrecking the tree)
  # falls back to a fresh extract: correct, only slower.
  sync_tree "$1" "$2" 2> /dev/null || { init_extract "$1" && sync_tree "$1" "$2"; } \
    || die "could not extract tree $2 to $1"
}

# The worktree's whole change as a tree, built in a scratch index.
whole_change_tree() {
  local tmp="$work/.whole-index"
  rm -f "$tmp"
  GIT_INDEX_FILE=$tmp git read-tree HEAD
  changed_files | tr '\n' '\0' | GIT_INDEX_FILE=$tmp git update-index --add --remove -z --stdin
  GIT_INDEX_FILE=$tmp git write-tree
}

case "${1:-}" in
  snapshot)
    # Re-snapshotting mid-split would clear a staged unit.
    if [ -d "$snap" ] && ! git diff --cached --quiet; then die "a unit is staged; land or unstage it first"; fi
    rm -rf "$snap"; mkdir -p "$snap"
    n=0
    while read -r f; do
      [ -f "$f" ] || continue
      mkdir -p "$snap/$(dirname "$f")"; cp "$f" "$snap/$f"; n=$((n+1))
    done < <(changed_files)
    git rev-parse HEAD > "$meta.head"
    git rev-parse --abbrev-ref HEAD > "$meta.branch"
    changed_files > "$meta.files"
    git reset -q
    echo "snapshot: $n files -> $snap"
    echo "base:     $(cat "$meta.head") on $(cat "$meta.branch")"
    echo "index:    cleared"
    ;;

  drift)
    [ -f "$meta.head" ] || die "no snapshot; run 'split.sh snapshot' first"
    base=$(cat "$meta.head"); now=$(git rev-parse HEAD)
    moved=0
    if [ "$base" = "$now" ]; then
      echo "base: unchanged ($now)"
    elif git merge-base --is-ancestor "$base" "$now"; then
      # Units the user committed on top of the pin: the expected move.
      echo "base: advanced by $(git rev-list --count "$base..$now") landed commit(s) to $now"
    else
      echo "base: MOVED $base -> $now (not a descendant: pull, rebase or branch switch)"; moved=1
    fi
    lost=0
    while read -r f; do
      if [ -f "$snap/$f" ] && [ -f "$f" ] && ! cmp -s "$snap/$f" "$f"; then
        echo "  differs from snapshot: $f"; lost=$((lost+1))
      elif [ -f "$snap/$f" ] && [ ! -f "$f" ]; then
        echo "  MISSING from worktree:  $f"; lost=$((lost+1))
      fi
    done < "$meta.files"
    # The worktree is read-only for the whole split, so any difference means it
    # drifted: a base move reverted a modified file, or something edited it.
    [ "$lost" = 0 ] && echo "worktree: matches snapshot" \
      || echo "worktree: $lost file(s) drifted — re-snapshot before continuing"
    [ "$moved" = 0 ] && [ "$lost" = 0 ]
    ;;

  stale)
    # Read-only: reports whether the change should move onto the latest
    # default branch before splitting. Fetch first; this does not.
    default=$(git symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null || echo origin/main)
    branch=$(git rev-parse --abbrev-ref HEAD)
    stale=0
    echo "branch:   $branch at $(git rev-parse --short HEAD)"
    if command -v gh > /dev/null; then
      pr=$(gh pr list --head "$branch" --state all --json number,state \
        --jq '.[0] | select(.) | "#\(.number) \(.state)"' 2>/dev/null || true)
      echo "pr:       ${pr:-none}"
      case "$pr" in *MERGED*|*CLOSED*) stale=1 ;; esac
    fi
    behind=$(git rev-list --count "HEAD..$default")
    echo "default:  $default at $(git rev-parse --short "$default"), $behind commit(s) not in HEAD"
    [ "$behind" = 0 ] || stale=1
    overlap=$(comm -12 <(changed_files | sort) \
      <(git diff --name-only "$(git merge-base HEAD "$default")" "$default" | sort))
    if [ -n "$overlap" ]; then
      echo "overlap:  changed files upstream also touched (the move merges these):"
      printf '  %s\n' $overlap
    else
      echo "overlap:  none"
    fi
    prefix=$(git branch --sort=-committerdate --format='%(refname:short)' | grep -m1 -o '^[^/]*/' || true)
    echo "prefix:   ${prefix:-none} (from recent branches)"
    [ "$stale" = 0 ] && echo "verdict:  current" \
      || echo "verdict:  STALE — propose: git checkout --no-track -b ${prefix}<stem> $default"
    [ "$stale" = 0 ]
    ;;

  stage)
    path="${2:?usage: split.sh stage <path> [<content-file>]}"
    if [ -f "$meta.files" ] && ! grep -qxF "$path" "$meta.files"; then die "$path is not part of the change"; fi
    src="${3:-$snap/$path}"
    [ -f "$src" ] || die "no content for $path (looked at $src)"
    mode=100644; [ -x "$src" ] && mode=100755
    sha=$(git hash-object -w "$src")
    git update-index --add --cacheinfo "$mode,$sha,$path"
    echo "staged $path <- ${3:-snapshot}"
    ;;

  rm)
    path="${2:?usage: split.sh rm <path>}"
    git rm -q --cached -- "$path"
    echo "staged removal of $path (worktree untouched)"
    ;;

  lock)
    # Resolve Cargo.lock for exactly the manifests in the index, offline, and
    # stage it. The diff against the snapshot's lock is the later units' part.
    [ -f "$snap/Cargo.lock" ] || die "the change does not touch Cargo.lock"
    extract_tree "$idx" "$(git write-tree)"
    ( cd "$idx" && cargo metadata --offline --format-version 1 > /dev/null ) || die "cargo could not resolve the index's manifests"
    sha=$(git hash-object -w "$idx/Cargo.lock")
    git update-index --add --cacheinfo "100644,$sha,Cargo.lock"
    echo "staged Cargo.lock <- resolved from the index"
    echo "--- lines later units still own:"
    diff "$idx/Cargo.lock" "$snap/Cargo.lock" | grep '^[<>]' || echo "(none)"
    ;;

  unstage)
    path="${2:?usage: split.sh unstage <path>}"
    git reset -q -- "$path"
    echo "unstaged $path (worktree untouched)"
    ;;

  base-version)
    path="${2:?usage: split.sh base-version <path> [<out>]}"
    out="${3:-$work/base/$path}"
    mkdir -p "$(dirname "$out")"
    git show "HEAD:$path" > "$out"
    echo "$out"
    ;;

  verify|check|baseline)
    mode="$1"; shift
    if [ "$mode" = baseline ]; then tree=$(whole_change_tree); else tree=$(git write-tree); fi
    # Same tree, same verdict: the last unit is the whole change, which the
    # baseline already ran. Only the authoritative run is recorded.
    verdict="$work/verdicts/$tree"
    if [ "$mode" != check ] && [ -f "$verdict" ]; then
      cp "$verdict.log" "$work/test.log"
      read -r fail failed < "$verdict"
      echo "=== $mode: $([ "$fail" -eq 0 ] && echo PASS || echo "FAIL:$failed") (recorded for tree $tree; log: $work/test.log)"
      exit "$fail"
    fi
    extract_tree "$idx" "$tree"
    # Tests that read gitignored fixtures (spec vectors, captured traces) cannot
    # find them in a detached extract; link them in from the real repo. Default
    # covers this repo's EF vectors; override with SPLIT_LINK="p1 p2".
    for rel in ${SPLIT_LINK-$(git status --porcelain --ignored | sed -n 's|^!! \(.*/\)$|\1|p' | grep -E "$FIXTURE_RE" || true)}; do
      rel="${rel%/}"
      [ -e "$repo/$rel" ] || continue
      [ "$(readlink "$idx/$rel")" = "$repo/$rel" ] && continue
      mkdir -p "$idx/$(dirname "$rel")"
      ln -sfn "$repo/$rel" "$idx/$rel"
      echo "linked fixture: $rel"
    done
    echo "=== extracted tree $tree -> $idx"
    cd "$idx"
    export CARGO_TARGET_DIR="$work/target"
    fail=0 failed=""
    if [ "$mode" != check ]; then
      # Authoritative: the repo's own recipes at the repo's own strictness.
      # Never substitute hand-rolled cargo flags — they differ (this repo's
      # clippy has no --all-targets; its nextest pins features and a profile).
      # `set -e` must not abort before the failure is reported, so every check
      # runs under `if !` and the log is always summarised.
      for r in fmt-check clippy; do
        if [ -f justfile ] && grep -q "^$r:" justfile; then
          if ! just "$r"; then echo "RECIPE FAILED: $r"; fail=1; failed+=" $r"; fi
        else
          echo "no '$r' recipe; skipped"
        fi
      done
      rc=0
      if [ -f justfile ] && grep -q "^nextest:" justfile; then
        just nextest > "$work/test.log" 2>&1 || rc=$?
      else
        cargo test --all-features > "$work/test.log" 2>&1 || rc=$?
      fi
      [ $rc -eq 0 ] || { echo "TESTS FAILED (rc=$rc)"; fail=1; failed+=" tests"; }
      # Test-code errors surface only here: this repo's `just clippy` has no
      # --all-targets, so it never compiles the test modules.
      sed 's/\x1b\[[0-9;]*m//g' "$work/test.log" |
        grep -aE "Summary|FAIL |test result:|^error" | tail -20 || true
    else
      # Iteration only: scoped and fast, not a substitute for 'verify'.
      # shellcheck disable=SC2086
      cargo clippy --all-features "$@" -- -D warnings $CHECK_CLIPPY_ALLOW \
        || { echo "CLIPPY FAILED"; fail=1; }
      rc=0
      cargo nextest run --all-features "$@" > "$work/test.log" 2>&1 || rc=$?
      [ $rc -eq 0 ] || { echo "TESTS FAILED (rc=$rc)"; fail=1; }
      grep -aE "Summary|FAIL " "$work/test.log" | tail -20 || true
    fi
    if [ "$mode" != check ]; then
      mkdir -p "$work/verdicts"
      cp "$work/test.log" "$verdict.log"
      echo "$fail$failed" > "$verdict"
    fi
    echo "=== $mode: $([ $fail -eq 0 ] && echo PASS || echo FAIL)  (log: $work/test.log)"
    exit $fail
    ;;

  union-check)
    [ -d "$snap" ] || die "no snapshot"
    bad=0
    while read -r f; do
      if [ ! -f "$snap/$f" ]; then
        # Deleted by the change: the index must not have it either.
        if git cat-file -e ":$f" 2>/dev/null; then echo "  deletion not staged: $f"; bad=1; fi
        continue
      fi
      if ! git show ":$f" > "$work/.staged" 2>/dev/null; then
        echo "  not in index: $f"; bad=1; continue
      fi
      cmp -s "$work/.staged" "$snap/$f" || { echo "  index != snapshot: $f"; bad=1; }
    done < "$meta.files"
    [ "$bad" = 0 ] && echo "union == original change" || echo "union INCOMPLETE (see above)"
    [ "$bad" = 0 ]
    ;;

  *)
    sed -n '2,4p' "$0"
    echo "usage: split.sh {baseline|snapshot|drift|stale|stage|rm|unstage|lock|base-version|verify|check|union-check}"
    ;;
esac
