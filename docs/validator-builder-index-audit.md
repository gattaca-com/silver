# Validator / builder identifier audit

Scope: every conversion, read, write and transform applied to a validator or
builder index in `silver`. The audit traced each identifier from its ingress
point (checkpoint SSZ, gossip, block body, API query) to its use as a slice /
storage index or as a hash-tree key.

Head audited: `617199c6` (working tree also contains an unrelated
`PayloadWithdrawals` refactor).

## Trust model

Identifiers enter through three boundaries:

1. **Checkpoint state** (`BeaconState::decompose` / `from_checkpoint`). The
   comment in `crates/beacon_state/data/src/checkpoint_state.rs` calls the
   downloaded state untrusted. At boot the state is only checked to hash to the
   provider-agreed block root (`roll_anchor`, `crates/beacon_state/tile/src/tile.rs:437`).
   The providers choose that root, and the state has no per-field range
   validation. A local `--checkpoint-file` / persisted checkpoint is equally
   unvalidated.
2. **Gossip and block bodies**, which carry u64 indices but are usually
   range-checked before use.
3. **API queries**, which are generally parsed with `usize::try_from` +
   `count()` checks.

The high-impact findings are all in class 1: state fields are decompressed as
raw `u64` and used directly as indexes. Class 2 and 3 are mostly sound.

Release-prod is built with `panic = "abort"` (`Cargo.toml`), so any of the
panics below terminates the process (DoS), not just a request.

## Findings

### F1 (High) `next_withdrawal_validator_index` used unchecked

- Load: `crates/beacon_state/data/src/slot_state/finalized.rs:83` (Gloas) and
  `:60` (Fulu) read `next_withdrawal_validator_index` straight from SSZ.
- Use: `crates/beacon_state/tile/src/stf/withdrawals.rs:136` starts the sweep at
  that value and immediately indexes `validators.credentials(vi as usize)`
  (`:141`), plus `balance_after` / `effective_balance` (`:143`, `:148`).
- The sweep only applies `% n` after the first iteration (`:162`), so an
  out-of-range initial cursor indexes `ValValidators::credentials` past
  `appended` and panics. `update_next_withdrawal_validator_index` (`:186-200`)
  normalises only after the panic point.
- Reachability: a checkpoint with `next_withdrawal_validator_index >= validators.count()`
  panics on the first payload/withdrawal processing after boot (Fulu
  `process_withdrawals_fulu`, Gloas `process_withdrawals`).
- Fix: validate `cursor < count` at decompose (or clamp/modulo before use) and
  use `% n` before the first access.

### F2 (High) `next_withdrawal_builder_index` used unchecked

- Load: `crates/beacon_state/data/src/slot_state/finalized.rs:89`.
- Use: `crates/beacon_state/tile/src/stf/gloas/withdrawals.rs:118` starts at the
  state cursor; `:124` does `builders.get(bi as usize).unwrap()`. `bi % n` only
  happens after the first iteration (`:139`).
- An out-of-range checkpoint cursor panics on `unwrap()`. The update at
  `:166-171` only normalises after the loop.
- Fix: range-check on load and `% n` before the first `get`.

### F3 (High) Pending partial-withdrawal `index` used unchecked

- Load: `crates/beacon_state/data/src/pending/finalized.rs:80-82`
  (`PendingPartialWithdrawal::read_ssz`: raw `u64`).
- Use: `crates/beacon_state/tile/src/stf/withdrawals.rs:103` (`let vi = pw.index`)
  then `balance_after` (`:104`), `exit_epoch` (`:105`), `effective_balance`
  (`:106`), `credentials` (`:112`). Fulu also converts it to `u32` in
  `apply_withdrawals` (`:307`).
- An out-of-range index panics in `balances.get` / validator column access. A
  value in `[2^32, 2^40)` silently truncates in `apply_withdrawals`, so the
  payload says `validator_index = 2^32+k` while the balance of `k` is debited.
- Normal enqueue (`operations.rs:240-244`) only ever stores `find_by_pubkey`
  results, so this is a checkpoint-only path.
- Fix: validate indices against the registry on decompose; assert
  `u32::try_from` success in the apply path.

### F4 (High) Pending consolidation `source_index` / `target_index` used unchecked

- Load: `crates/beacon_state/data/src/pending/finalized.rs:100-102`: both are
  raw `u64`.
- Use: `crates/beacon_state/tile/src/stf/epoch.rs:675` (`let src = pc.source_index as u32`)
  then direct `is_slashed(src)`, `withdrawable_epoch(src)`, `balances.get(src)`
  (`:676`, `:681`, `:684`); `tgt` likewise at `:683-689`.
- Out-of-range values panic in the epoch transition (`process_pending_consolidations`
  runs every epoch, `stf/epoch.rs:81`). Values in `[2^32, 2^40)` truncate and
  move balance between the wrong validators — a consensus divergence, not just a
  crash.
- Fix: validate both fields on decompose, and use `u32::try_from` (not `as`)
  with a checked index.

### F5 (High) Builder index from pending payments / withdrawals used unchecked

- Load:
  - `BuilderPendingWithdrawal::from_ssz` (`crates/beacon_state/data/src/pending/finalized.rs:123-124`)
  - `read_pending_payments` (`crates/beacon_state/data/src/slot_state/finalized.rs:113`)
  - `latest_execution_payload_bid.builder_index` (`crates/beacon_state/data/src/gloas.rs`)
- Propagation:
  - `process_builder_pending_payments` pushes `payment.withdrawal`
    (`stf/gloas/builders.rs:64`) without checking the index.
  - `apply_parent_execution_payload` pushes `parent_builder_index` from the
    state bid (`stf/gloas/parent_payload.rs:75-82`).
  - `get_builder_withdrawals` converts and pushes the queue entry without
    checking (`stf/gloas/withdrawals.rs:91-97`).
- Use: `apply_withdrawals` converts back and calls
  `view.builders.sub_balance(bi, ...)` (`stf/gloas/withdrawals.rs:156-157`),
  which does `.expect("sub_balance: index out of range")`
  (`crates/beacon_state/data/src/builders/delta.rs:217-219`).
- A checkpoint with an out-of-range or `BUILDER_INDEX_SELF_BUILD` builder index
  in either queue reaches this panic. Note `BUILDER_INDEX_SELF_BUILD = u64::MAX`
  is only safe while a self-build has `value == 0`; a corrupted checkpoint can
  pair it with a non-zero amount.
- Fix: validate `builder_index < builders.len()` on decompose/queue build, or
  make `sub_balance` return an error instead of `expect`.

### F6 (High) PTC window indices used unchecked during block import

- Load: `crates/beacon_state/data/src/epoch/finalized.rs:53-67` reads the whole
  `ptc_window` as raw `u64` values.
- Use: `crates/beacon_state/tile/src/stf/gloas/payload_attestation.rs:103-105`
  does `validators.pubkey_decompressed(ptc[i] as usize)` for every set
  aggregation bit, with no `count` check.
- A block carrying a payload attestation whose bits select an out-of-range PTC
  entry panics. The block proposer controls the bits, so with a malicious
  checkpoint this is triggered by the first payload attestation.
- `compute_ptc` (`stf/gloas/committee.rs:47-80`) only stores in-range indices
  for honest states, and the empty-committee fallback is all-zero (index 0),
  which is in range whenever `count > 0`.
- Fix: range-check PTC entries at decompose (or skip/reject out-of-range entries
  in `collect_sigs_payload_attestation`).

### F7 (High) Proposer lookahead used unchecked / truncated

- Load: `crates/beacon_state/data/src/epoch/finalized.rs:69-77`
  (`read_epoch_state` reads `proposer_lookahead` as raw `u64`).
- Uses without a `count` check:
  - `crates/beacon_api/src/validator/proposer_duties.rs:88`
    `*view.validators.pubkey(proposers[offset] as usize)` — a corrupt lookahead
    turns an API request into a panic.
  - `crates/beacon_state/tile/src/stf/validator.rs:204-208`
    `get_beacon_proposer_index` truncates the lookahead value to `u32`.
  - `crates/beacon_state/tile/src/tile/gossip.rs:1082-1095`: gossip first
    compares against the lookahead, then indexes `pubkey_decompressed(validator_index as usize)`.
  - `crates/beacon_state/tile/src/tile/block_production.rs:578,634,709` index
    the proposer without a check.
- Honest transitions derive the lookahead from active validators, so this is
  checkpoint-only, but the API path makes it remotely triggerable once a bad
  state is loaded.
- Fix: validate every lookahead entry against the registry on load; keep the
  lookup `Option`-based in the API/STF.

### F8 (Medium/Latent) u64 -> u32 narrowing across the registry

All internal validator/builder index storage is `u32`, while
`VALIDATOR_REGISTRY_LIMIT` / `BUILDER_REGISTRY_LIMIT` are `2^40`. Any count
above `2^32` silently aliases:

- `crates/beacon_state/data/src/validators/delta.rs:73` (`promote_into_base`
  inserts `idx as u32`), `:100` (`new_count as u32`), `:326-340`
  (`find_by_pubkey` / `find_by_finalized_pubkey` return `u32`), `:450`
  (`active_indices_into` pushes `i as u32`), `:675` (`append` returns `idx as u32`).
- `crates/beacon_state/data/src/validators/finalized.rs:204`
  (`index.insert(pubkey, i as u32)`).
- `crates/beacon_state/data/src/sparse/edits.rs:44-48`: `Edits::get` uses
  `u32::try_from(idx).ok()?`, so an edit for a >2^32 index is silently ignored.
- `crates/beacon_state/data/src/builders/delta.rs:52` (`new_count as u32`),
  `:188` (`hash.set(i as u32, ...)`), `:204`, `:212`.
- `crates/beacon_state/tile/src/stf/epoch.rs:398` (`for vi in 0..n as u32`).
- `crates/beacon_state/tile/src/stf/operations.rs:432`
  (`set_credentials(validator_index as u32, ...)`).
- `crates/beacon_state/tile/src/stf/slashings.rs:64,103,176,262,333,366`.
- `crates/beacon_state/tile/src/stf/gloas/withdrawals.rs:159`,
  `stf/withdrawals.rs:307`.

`FinalizedValidators::try_new` (`validators/finalized.rs:230-272`) does not
enforce `VALIDATOR_REGISTRY_LIMIT`, unlike `FinalizedBuilders::from_ssz`
(`builders/finalized.rs:30-40`). A state able to reach `2^32` validators would
therefore corrupt lookups before the nominal `2^40` limit. Practically requires
an enormous (multi-TB) state blob, so this is latent, but it is a real
consistency gap and a consensus-divergence risk.

### F9 (Medium) Exit / BLS-change pool key truncation

- `crates/beacon_state/tile/src/tile/exit_pool.rs:31`,
  `crates/beacon_state/tile/src/tile/bls_change_pool.rs:34`,
  `crates/beacon_api/src/beacon/pools.rs:36,43` all use
  `validator_index(...) as u32` as a map key.
- Gossip validates `vi < count` before insertion (`gossip.rs:1597,1733`), so
  this is only wrong for `count >= 2^32`; then two distinct validators alias
  one pool slot and one operation can be lost/replaced.
- Fix: keys `u64`, or `u32::try_from(vi)` with a reject.

### F10 (Low) Builder balance / obligation overflow

- `BuilderRegistry::pending_balance_to_withdraw`
  (`crates/beacon_state/data/src/builder_registry.rs:79-92`) accumulates
  `u64` withdrawal amounts with `total +=`. Release has `overflow-checks = false`,
  so the sum wraps.
- `can_cover_bid` (`:96-99`) adds `MIN_DEPOSIT_AMOUNT + total`, which can also
  wrap, and `balance - min_balance` assumes `balance >= min_balance`.
- `BuildersWriteView::add_balance` (`builders/delta.rs:209-213`) does
  `b.balance += amount` unchecked.
- `get_pending_balance_to_withdraw` (`stf/validator.rs:161-170`) and
  `accrue_builder_payment_weight` (`stf/attestation.rs:483`) have the same
  unchecked accumulation.
- Over-committing a builder would require accumulating more than `2^64` wei of
  pending payments, so this is latent. Fix with `checked_add` /
  `saturating_add` and a rejection path.

### F11 (Low) Cursor update arithmetic

- `update_next_withdrawal_builder_index` (`stf/gloas/withdrawals.rs:169`) does
  `cursor + processed_sweep` before `% n`; a near-`u64::MAX` checkpoint cursor
  wraps. F2 panics first, but the expression should still be
  `cursor.saturating_add(...)` / checked.
- `update_next_withdrawal_index` (`stf/withdrawals.rs:179-181`) does
  `last.index + 1` unchecked.

## Paths checked and found sound

- API `ValidatorId` / `BuilderId` resolution: `usize::try_from` plus
  `ix < count` (`beacon_api/src/beacon/validators.rs:330-338`,
  `beacon_api/src/beacon/builders.rs:111-117`).
- Gossip voluntary exits / BLS changes / sync messages / aggregate-and-proof /
  PTC messages: `validate_exit_eligibility`
  (`tile/src/validate.rs:129-131`), `validate_bls_to_execution_change` (`:152-155`),
  `gossip.rs:656-657,745-746,1208-1209,1733-1734`, `fork_choice.rs:214`.
- STF proposer slashings / attester slashings / voluntary exits / BLS changes:
  `vi < count` before narrowing (`stf/slashings.rs:61,100,170`,
  `stf/operations.rs:64,102`).
- Attestation committees: `check_indices_addressable`
  (`stf/attestation.rs:150-160`) and shufflings built from
  `active_indices_into`.
- Sync aggregate: `(vi as usize) >= count` checks in both passes
  (`stf/sync_aggregate.rs:50-53,116-118`).
- Payload envelope builder lookup uses `builders.get(...).ok_or(...)`
  (`stf/gloas/envelope.rs:146-147`).
- Fulu header validation uses `usize::try_from` + bounds
  (`columns/src/validate/fulu_header.rs:66-69`).
- `SyncSubcommittee` treats `u32::MAX` as unresolved and bounds-checks
  (`data/src/longtail/sync_subcommittee.rs:75-85`).
- `PayloadWithdrawals` matches in `stf/gloas/envelope.rs` compares values only.
- Block production / shuffling cache / API committees use shuffling indices
  derived from active validators (in range) and check query committee indices.

## Recommended order of fixes

1. F1, F2, F3, F4, F5: validate every checkpoint-loaded identifier against the
   registry/builder-registry count during decompose (single helper called from
   `assemble`), and make the sweep/apply paths use `% n` + checked access.
2. F6, F7: range-check PTC and proposer-lookahead arrays at load; make the
   consumer lookups return `Option`/false instead of panicking.
3. F5/F10: replace `sub_balance`/`add_balance` `expect`/unchecked arithmetic
   with checked operations.
4. F8: either enforce `VALIDATOR_REGISTRY_LIMIT`/`BUILDER_REGISTRY_LIMIT` and
   the `u32` internal limit at decompose, or move internal indices to `u64`.
5. F9/F11: keys `u64`, checked cursor arithmetic.

No source files were changed for this audit; this document is the only new
artifact.
