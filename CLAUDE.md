# CLAUDE.md

Guidance for working on **silver** — Gattaca's high-performance Ethereum consensus client.

## Philosophy

Two principles drive every rule below:

- **Simplicity.** Simplicity is the foundation of capability, not the opposite of it.
  Favour fewer abstractions, fewer layers, fewer traits, fewer macros. Reach for
  the language's existing tools before inventing new ones.
- **Performance.** Performance is a feature, not an afterthought. Hot paths (state transitions,
  finalization, hashing, gossip ingestion and propagation) are measured. When two designs are equally clear,
  pick the faster one; when the fast one is less clear, justify it and measure it.

These reinforce each other: a smaller, flatter, well-named codebase is both simpler to
reason about and faster to run.

## Project shape

- Binary is `crates/bin`; everything else is a `silver_*` library crate.
- Most crates are organised as **tiles** — independent components that communicate over channels.
- The beacon state is **not** a monolith: it's a bag of per-tier *groups* (validators,
  balances, participation, …), each a finalized base + a ring of per-fork deltas.
- Read `docs/beacon-state-architecture.md` and `docs/delta-rebase-invariant.md` before
  touching state storage. Other refs: `docs/perf-regression-test.md`,
  `docs/p2p-ladder-diagrams.md`.

## Build / test / lint

Use the `justfile` — don't invent your own cargo invocations:

- `just fmt` / `just fmt-check` — **always format with this, never `cargo fmt`.** It pins
  the nightly that honours `rustfmt.toml`; stable `cargo fmt` ignores the nightly-only
  options and churns the whole workspace.
- `just clippy` — `--all-features -D warnings` (with `collapsible_if` allowed).
- `just test` / `just nextest` — mirrors CI: every crate, with
  `silver_beacon_state/ef_tests` and `silver_e2e/lh-client` features on.
- **Verify with `--all-features`.** Feature-gated test binaries (`ef_tests`, e2e
  `lh-client`) are invisible to a plain `cargo check --all-targets`; a change that compiles
  without features can still break them.

## Code style — the two things that matter most here

### 1. Comments must carry information the code cannot

- The default comment count on fresh, well-named code is **zero**, not "shorter". A comment
  earns its place only by stating something the reader can't get from the signature, types,
  names, or a short body in front of them — primarily a *why*, secondarily a non-obvious
  invariant or asymptotic.
- Delete or never write comments that:
  - **Restate the signature/name** — `fn promote_into_base(&self, base: &mut Finalized)`
    doc'd as "Fold this fork's delta into base" carries nothing. Same for `pub struct`
    preambles paraphrasing the type, per-field `///` restating the field, `//!` headers
    respelling the module. `pub` does not earn a doc.
  - **Leak out of the subject's abstraction layer** — a comment on `A` describes `A`'s
    contract in `A`'s vocabulary, never reaching into sibling `B`'s internals ("promoted by
    `B::foo`", "called in parallel with…"). Those rot and signal unclear naming.
  - **State a precondition in prose** — "caller must ensure `x > 0`" / "only valid after
    init" belong in `debug_assert!` / `assert!`: they document *and* enforce.
  - **Dwarf their subject** — a multi-line preamble over a short fn/module with no
    non-trivial fact justifying the length.
- **Prefer renaming/restructuring over commenting:**
  - Vague helper + explaining comment → rename the helper so the call site reads as what it
    returns.
  - Magic literal + comment → encode the derivation in the value (`512 / 8`, not
    `64 // 512 bits`).
  - Long param-by-param doc → the signature or names should change so structure carries the
    meaning.
- **Exception — never delete logging.** `tracing::*!` / `log::*!` calls are live debugging
  surface; the author is often actively using them. Leave them unless the user asks for log
  cleanup or the whole code path is being deleted. (`println!` / `eprintln!` in non-test,
  non-CLI paths *are* stray scaffolding — remove or convert.)

### 2. Encapsulation: data owns its methods; distinct components get their own file

The goal when pulling apart "logically different components" is real ownership and type
boundaries — not the same implementation sprinkled across more files.

- **Data owns its methods.** A function operating on a struct's data is a method on that
  struct, not a free function. When **≥2 free functions thread the same `&[T]` / `&Vec<T>`
  / value-bundle**, the missing owner *is* the smell: introduce a newtype that owns the data
  and make them methods. "It's a slice" and "it has many call sites" are the **triggers** to
  wrap, not reasons to stay free — `foo.render()` beats `render(&foo)` precisely when there
  are many callers.
- **`// ── X ──` banner comments are unwritten function names.** A divider carving a long
  function or module body into phases means: extract each region into a helper named for the
  banner, then delete the banner. A wiring/setup block producing many entangled locals is
  the *constructor* of an owner type.
- **One file = one struct/responsibility.** Calculation logic and rendering logic live in
  separate files. When a module grows, use subdirectories — *but* don't over-split:
  consolidate code that is genuinely one responsibility. A near-empty file with a single
  10-line type is overhead; fold it into its primary consumer.
- **Cohesive field subsets want their own type.** Fields that share a prefix, are always set
  together, toggle `Some`/`None` in lockstep, or are touched only by the same subset of
  methods → extract a dedicated struct (derivation logic goes in its constructor). A state
  machine (enum discriminant + state fields + transition methods) owns *both* its data and
  its transitions; the parent holds one field and delegates.
- **Don't split implementation just to split it.** Splitting one struct's `impl` across
  files, or factoring a single responsibility into modules that all need each other's
  internals, is worse than one cohesive file. Split when responsibilities are distinct and
  the boundary reduces coupling — not to hit a line count.
- **Put code in the most general crate that makes sense** for reuse, and keep tightly
  coupled macros in the same module as what they generate.

### Other conventions (lower friction, still enforced)

- **Imports, not inline paths** — `use crate::a::b::Type;` at the top, never
  `crate::a::b::Type` inline in a body or signature.
- **Omit inferred types** — drop annotations the compiler infers (`Vec<_>` over
  `Vec<Concrete>` when usage constrains it). Keep them only at public boundaries or to
  disambiguate.
- **Readability over brevity** — named structs > anonymous tuples; full names (`slot_data`)
  over abbreviations *unless* the surrounding params already use type-abbreviations
  (`sd: &SlotData`, `pq: &mut PendingQueues`), then match that idiom. Blank lines between
  distinct phases of a function.
- **Names track current reality** — after a refactor changes *what* something is, rename
  fields/params/files/locals that still encode the old identity. `anchor_*`/`base_*` names
  must not be on fields mutated every push. A single-primary-`pub`-type file is named after
  that type.
- **Reuse before inventing** — don't create a struct whose only justification is a
  clone+rearrange conversion from an existing one. Prefer generics/closures over
  `macro_rules!`. Use existing macros/traits/helpers; type-alias a generic instantiation
  repeated 4+ times in a file.
- **Question every intermediary** — pass `&dependency` instead of hand-projecting 3+ of its
  fields as separate params (for sibling components under one owner). Inline single-use
  forwarders and pure-delegation wrappers (`fn x(&self) { self.inner.x() }`).

## Performance

- **Measure, don't guess.** Profile before optimizing and confirm the win with numbers
  after — the real bottleneck is often not the obvious suspect (here it's been alloc /
  tree-walk and state hashing). There is no workspace-wide perf harness; each tile is
  measured on its own terms, so reach for the tile's own benchmark, a targeted profile, or
  ad-hoc timing rather than assuming.
  - *Beacon state specifically:* `just perf-local` runs the regression harness on committed
    mainnet fixtures (CI runs it too). See `docs/perf-regression-test.md`. This harness covers
    **only** the beacon-state path, not other tiles.
- **Compute once; batch.** Don't recompute near-constants per call. Aggregate before sending
  instead of per-item operations. Don't iterate the same collection multiple times with
  different filters when one sorted pass suffices.
- **Watch allocation on hot paths.** Per-node `Arc`/`Box` allocation and redundant clones
  dominate state apply/finalization cost; prefer arenas and reuse over per-element heap
  traffic. A simplification that adds allocation to a measured path is a regression —
  justify it with numbers.

## Discipline

- **Minimal diff.** Don't "improve" working code outside the task. But code the *current
  diff introduced* is in scope to fix even when the fix is larger/non-local (extracting a new
  module, rewiring imports) — edit size is not a scope test. Performance and avoidance of
  undue coupling (e.g. between tiles) take priority over this rule.

## Communication

Applies to prose you write into:

- commit messages
- GitHub issues, and comments on issues
- pull request descriptions, and review comments
- code comments
- documentation committed to the repository

Rules:

- Default to sentences under 25 words.
  - Write a longer sentence when splitting it would hide how the parts relate.
  - Use a list if the content does not fit in one sentence.
- Do not split a sentence into fragments to meet the limit.
- One main clause per sentence. Subordinate clauses are fine.
- Use no more than three nouns in a noun cluster.
- Use one term per concept, and one concept per term.
- State uncertainty and untested assumptions in reviews, issues, and pull request descriptions.
  - Do not drop them for brevity.
- Reproduce commands, code, identifiers, paths, and quotations verbatim.
  - These rules do not apply to them.
- Do not try to fix the language produced by others to follow these rules.
  - For example, this document.

## Issue tracking

Track project work in GitHub issues. Only use Linear or other platforms when
explicitly asked.
