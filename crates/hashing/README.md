# silver_state_hashing

Merkle hashing for Ethereum beacon states. It rehashes only changed paths in
batched SIMD calls. Forks share unchanged data in copy-on-write pages.

It hashes SSZ `List`, `Vector` and EIP-7916 `ProgressiveList` of `u8`,
`u64` and `B256`. A list of containers stores each element's root as a
`B256` leaf.

## How it works

### Flat tree

The tree is one flat array of 32-byte nodes. The root sits at index 1, and
node `i` has children `2i` and `2i + 1`. Each level is a contiguous slice,
and the leaves pack the values, such as four `u64` per leaf.

A write marks its leaf. A rehash then hashes the marked ranges level by
level, from the leaves up. Writes to `l2..l5` and `l7` rehash like this:

```text
index    1 | 2   3  | 4   5   6   7  | 8   9   10  11  12  13  14  15
node     r | a0  a1 | b0  b1  b2  b3 | l0  l1  l2  l3  l4  l5  l6  l7
written                                        *   *   *   *       *

pass 1   b1 b2 b3  <-  l2 .. l7    nodes 5..8  <- 10..16    one batched call
pass 2   a0 a1     <-  b0 .. b3    nodes 2..4  <-  4..8     one batched call
pass 3   r         <-  a0 a1       node  1     <-  2..4     one batched call
```

The writes form two ranges, `l2..l5` and `l7`. Their parents `b1..b3` form
one range, so pass 1 hashes them together. `b0` keeps its old hash, and pass
2 uses it as an input to `a0`.

Each batched call hashes many pairs at once with SIMD. Random writes are
usually sparse, so their parents rarely sit side by side. For those, the
pairs are copied into a group of 16 and hashed in one SIMD call. The results
are then copied back into the array.

### Pages

A commit cuts the flat tree into pages. A page is the mini-tree under one
node. The same eight leaves, in pages of four nodes:

```text
      ┌─────────────────────────┐
      │            1            │      page level 1: the root page
      │  2                   3  │
      └──┬───────────────────┬──┘
    ┌────┴────┐         ┌────┴────┐
┌───┴───┐ ┌───┴───┐ ┌───┴───┐ ┌───┴───┐
│   4   │ │   5   │ │   6   │ │   7   │
│ 8   9 │ │ 10 11 │ │ 12 13 │ │ 14 15 │ page level 0: the leaf pages
└───────┘ └───────┘ └───────┘ └───────┘
```

A page stores its nodes row by row. Each row is already contiguous in the
flat tree, so a page is filled with one copy per row:

```text
flat tree:  _ | 1 | 2 3 | 4 5 6 7 | 8 9 10 11 12 13 14 15
page 5:     _ | 5 | 10 11     copies node 5, then nodes 10 11
root page:  _ | 1 | 2 3       copies node 1, then nodes 2 3
```

The page size is set per list by `TreeSpec::Page`.

Pages are copy-on-write. With the pages above, `R` holding nodes `1 2 3` and
`P4..P7` the leaf pages, an edit on a clone goes like this:

```text
B = A.clone()      A ──► R   P4  P5  P6   P7
                   B ──► R   P4  P5  P6   P7     every page shared

B.set(leaf 12)     B writes leaf 12 in its flat tree; no page changes yet

B.commit()         B rehashes nodes 6, 3 and 1, then writes new pages to storage:
                   A ──► R   P4  P5  P6   P7
                   B ──► R'  P4  P5  P6'  P7     R' and P6' new, rest shared
```

A keeps its pages untouched. A page links to its child pages, so a committed
list is just its root page id. `R` rebuilds A and `R'` rebuilds B. A
progressive list keeps one root page per segment.

Switching between A and B costs only the pages where they differ, here `R`
and `P6`.

## Use

```sh
cargo add silver_state_hashing --features multi-owner
```

Hashing goes through `hashtree-rs`, which builds C and assembly. A C toolchain
is required.

Declare each list by its element type, page size, SSZ limit, and whether it
is a `List` or a `Vector`:

```rust
use silver_state_hashing::{B256, HashFormat, SharedList, TreeSpec};

struct Balances;

impl TreeSpec for Balances {
    type Val = u64;
    type Page = [B256; 128];
    const SSZ_LIMIT: usize = 1 << 40;
    const IS_LIST: bool = true; // false for an SSZ Vector
}

let values = vec![32_000_000_000; 1_000_000];
let head = SharedList::<Balances>::new(&values, HashFormat::Fixed /* or Progressive */).unwrap();
let root = head.hash_root();

let mut fork = head.clone();
fork.set(7, 31_000_000_000).unwrap();
fork.commit();
assert_ne!(fork.hash_root(), root);
```

Small pages favour scattered writes, and large pages favour bulk rewrites.

| Method | What it does |
|---|---|
| `set`, `push` | Write into the list's flat tree. A `push` past the capacity doubles the tree with a memcpy, not a rehash. |
| `commit` | Rehashes the written paths and stores changed pages. Then it parks the flat tree, so the next first write on a clone reloads only the pages that differ. |
| `hash_root` | Returns the root of a committed list. It asserts that the list is committed. |
| `clone` | One atomic increment per root page. A clone with uncommitted writes also copies the flat tree. |
| `Drop` | Releases the list's root pages. A page that no list or parent page uses any more is freed, and releases its child pages in turn. Runs on whichever thread drops. |
| `migrate_to_progressive` | Switches the list to EIP-7916 hashing. |

## Storages

**Multi-owner:** `SharedList` counts references per page, like an `Arc`.
Clone a list and drop it on any thread; a page is freed when no list uses it.
It needs the `multi-owner` feature, which is off by default.

**Single-owner:** `PagePool` + `PageSnapshot` keeps no counts. One thread
holds every version of a list and frees pages explicitly. It is built for
silver's state design.

## Benchmarks

Compared with `milhouse` 0.9 and `ssz::PersistentList`, the persistent list
of another Rust consensus client, on a mainnet-sized list of 2.3M entries.
All writes go to 900k non-zero entries, and each time covers the writes and
the new root. Every library's root is checked against ours before timing.
`ssz::PersistentList` hashes on one thread, with the 64-value bundle its
client uses for balances. Measured on an AMD Ryzen 9 9950X, 16 cores, with
mimalloc for all; scenarios are in
[`comparison.rs`](https://github.com/gattaca-com/silver/blob/main/crates/hashing/bench/benches/comparison.rs).

| Scenario | silver_state_hashing, 1 thread | ssz::PersistentList | milhouse, 1 thread | milhouse, 16 threads |
|---|---|---|---|---|
| Build + root | 14.3 ms | 36.0 ms | 133 ms | 66.3 ms |
| Iterate all values | 0.21 ms | 0.31 ms | 19.2 ms | - |
| 500 random writes | 0.36 ms | 0.77 ms | 6.36 ms | 6.08 ms |
| 2,000 random writes | 0.94 ms | 2.75 ms | 11.2 ms | 9.34 ms |
| 900k writes, one per non-zero entry | 16.3 ms | 61.2 ms | 241 ms | 154 ms |
| Reorg depth 1 + 500 writes | 0.43 ms | 0.74 ms | 6.58 ms | 6.13 ms |
| Reorg depth 4 + 500 writes | 1.18 ms | 0.74 ms | 6.71 ms | 6.65 ms |
| Reorg depth 32 + 500 writes | 2.85 ms | 0.75 ms | 7.14 ms | 6.58 ms |

Switching versions takes longer here than in the other libraries. The design
targets the real use case: on mainnet, fewer than 0.15% of blocks are reorged
out, and 99.8% of reorgs are one block deep.

```sh
cargo bench -p silver_state_hashing_bench
```
