The retention stage now covers the shared collections below. Reclamation epochs
remain planned: they are logical memory generations, independent of consensus epochs and elapsed time.

[`RetiredColumns`](../crates/state_memory/src/retired_columns.rs) retains replaced
allocations until its owner drops. Finalized columns use its boxed-slice growth helper.
[`RetainedVec`](../crates/state_memory/src/retained_vec.rs) uses the same queue for
growing vectors. Copying and clearing preserve each destination's retirement history.
Neither helper synchronizes collection metadata or in-place element writes.

`BeaconStateReader::read` and `read_pinned` now expose a restricted `StateReadView`.
It excludes Eth1 votes, pending queues, effective increments, and historical summary entries.
Its longtail view also hides `LongtailState`, whose clone would read the summaries allocation.
Owner-side `StateView` retains these accesses. Checkpoint encoding keeps its existing promotion locks.

| Storage | Current retention | Planned change |
|---|---|---|
| Nine finalized validator columns | `RetiredColumns`, populated by `FinalizedValidators::grow` | Safe descriptor publication and epoch reclamation |
| Finalized builder registry | `RetiredColumns`, populated by `FinalizedBuilders::ensure_capacity` | Same protocol as validator columns |
| Old ring generations | Atomic publication; retained until `Ring::drop` | Optional later migration to the same reclamation domain |
| Validator and builder `appended` | `RetainedVec` preserves replaced allocations through reanchoring and slot reuse | Safe descriptor publication and epoch reclamation |
| Validator and builder `Edits.inner` | `RetainedVec` covers reserve, merge, and copy | Same protocol as appended records |
| `PageTable.roots` | Inline array of 32 page IDs and a logical root count | No allocation retirement needed; metadata publication remains separate |
| State-owned `blob_kzg_commitments` | `RetainedVec`; promotion, copying, assignment sites, and reset preserve history | Safe descriptor publication and epoch reclamation |
| `SlotState.payload_expected_withdrawals` | Inline `PayloadWithdrawals` | No allocation retirement needed |
| PTC committees and roots | Fixed boxes reused during copying and replacement | No allocation retirement needed |

The nine validator columns are pubkeys, decompressed pubkeys, credentials,
effective balances, the slashed bitset, and four epoch columns.
Their finalized storage now grows, so treating them as permanently fixed is outdated.

Ring entries retain their wrappers during reset and reuse. Replacing an entire
wrapper would discard its history, so existing assignment sites now copy into it.
New clones have independent allocations and retirement histories.

1. Extend the existing retirement mechanism.

   Keep `RetiredColumns` as the initial integration point. Add allocation sizes
   and a way to transfer pending allocations into epoch-tagged batches.
   Its internal vector is writer-only; its own reallocation needs no reader protection.

   The storage primitives live in `silver_state_memory`, used by
   `silver_beacon_state_data`. Add the domain there; `silver_common` would introduce a dependency cycle.

   The domain contains a monotonically increasing epoch and three stable,
   padded reader counters. Writer-owned queues hold protected batches and
   allocations already eligible for freeing.

   Existing per-base queues can be drained into a batch during maintenance.
   Tag that batch with the current epoch after removal from publication.
   Tagging later than the replacement conservatively retains allocations longer.
   Keep allocations owned throughout transfer and preserve pending queues during shutdown.

2. Register every shared read attempt.

   Reader entry loads the epoch, increments its bucket, and rechecks the epoch.
   If it changed, decrement and retry before accessing state.
   A guard decrements the counter on return, retry, error, or unwinding.

   Pin before reading the control/version snapshot that authorizes state access.
   Release the guard while retrying an open finalization window.
   Start with sequentially consistent atomics and model-test before weakening ordering.

   Cover `read`, `read_pinned`, checkpoint capture, and checkpoint chunk encoding
   in [`view.rs`](../crates/beacon_state/data/src/view.rs).
   Release guards between attempts and checkpoint chunks.
   `PinnedState` remains a version token; storing it does not pin an epoch.

3. Make column publication compatible with concurrent readers.

   `RetiredColumns::grow` currently uses `mem::replace` on a plain `Box<[T]>`.
   Retention keeps the backing allocation alive, but does not synchronize reads
   of the box's pointer and length. Existing version checks do not remove that race.
   [`UnsafeCell` does not prevent data races](https://doc.rust-lang.org/std/cell/struct.UnsafeCell.html).

   Publish an atomic pointer to an immutable allocation descriptor containing
   the backing pointer and capacity. Readers capture one descriptor under their guard.
   Retire the old descriptor together with its allocation.
   Coordinate logical counts with the selected storage generation before dereferencing.

   Apply this to both finalized registries before enabling their reclamation.
   Keep `T: Copy` for the initial column implementation, matching the existing helper.
   Avoid moving unique owning boxes through readers' live reference paths;
   reconstruct ownership for destruction only after the grace period.

   This stage addresses allocation lifetime and metadata publication.
   In-place element writes and broad shared/mutable state aliases need separate treatment.
   Do not describe the whole `BeaconStateReader` API as sound after this stage.

4. Reclaim through a reader-gated epoch wheel.

   The ordering is:

   ```text
   populate replacement
     -> publish replacement descriptor
     -> retain old descriptor and allocation
     -> collect into a batch tagged E
     -> advance the domain epoch
     -> reclaim after all readers in E or earlier finish
   ```

   Require `retired_epoch < current_epoch` and no active reader in an epoch
   at or before the retirement epoch. Checking only bucket E is insufficient.
   Readers admitted in later epochs do not keep older batches alive.

   Never recycle a protected generation's bucket. Never reset reader counters
   during recycling; delayed registrations still need to decrement their increments.
   Compare full epochs on admission, including when a bucket is reused.
   Move eligible allocations to the ready queue before reusing batch metadata.

   A stalled reader can stop rotation and reclamation. Writes continue and
   append retirements to the current batch, accepting increased retained memory.
   Do not free based on a timeout or an isolated zero-reader count.

   The existing [`Wheel`](../crates/common/src/wheel.rs) clears buckets by time.
   Its eviction policy cannot implement this grace period.

5. Drive collection and destruction from the beacon tile.

   Add `BeaconStateOwner::maintain_reclamation(budget)` at the end of the outer
   [`BeaconStateTile::loop_body`](../crates/beacon_state/tile/src/tile.rs).
   This covers both syncing and following, after temporary state borrows finish.

   Drain pending retirements, advance epochs when allowed, move eligible batches,
   and free a bounded number of allocations. Skip scans when no retirement is pending.
   Destruction stays on the beacon tile during normal operation.

   Call `adapter.mark_work()` when maintenance progresses.
   Allow parking when readers prevent further progress.
   Arm and recheck a cleanup notification before parking; reader exit signals
   when it may release the obstruction. Model-test this handshake against lost wakeups.
   Use the existing Flux signal; no new `Tile` methods are needed.
   Avoid signaling on every ordinary read: the current signal wakes all parked tiles.

   Reader metadata and retained allocations must share `StateCell`'s lifetime.
   Dropping `BeaconStateOwner` must not destroy batches while a reader still holds state.
   Final shared-state destruction can release the remaining queues after readers are gone.

6. Extend reclamation after finalized-column reclamation works.

   Integrate the retained `appended`, `Edits.inner`, and bid
   commitments into the domain. Preserve coverage of copying, reset, growth, and drop.

   A reused ring slot can still have readers from its previous publication.
   Calling it unpublished does not make its existing allocation exclusively owned.
   Detach and retain that storage before any replacement could free it.
   Ordinary allocation remains appropriate for genuinely private working buffers.

   Publish vector descriptors at commit boundaries where possible.
   Avoid allocating descriptors per push or per sparse edit.
   Page tables need consistent reads of inline roots, format, and count.
   Inline roots do not prevent `PagePool` from recycling the referenced pages;
   that reuse remains a separate issue.

   Keep existing promotion locks for pending queues and historical summaries.
   Their checkpoint reads already use locked paths. Audit any expansion of the
   shared read API before exposing additional reallocating storage.

   Old ring generations can join the domain later to recover their retained memory.
   Preserve `PageSnapshot::clone_for_grow` ownership: dropping an old ring must
   not release pages whose ownership moved to its replacement.

7. Validate lifetime, progress, and cost.

   Existing registry growth tests verify values and hashes after promotion.
   They do not hold concurrent readers or test delayed reclamation.

   Model-test admission versus rotation, late increments, bucket reuse, overlapping
   and nested reads, and the cleanup wakeup handshake.
   Add deterministic allocation/drop checks across registry growth, reader retries,
   errors, panic unwinding, checkpoint chunks, and owner shutdown.
   Verify that newer readers do not prevent an older batch from being reclaimed.

   Add gauges for active readers, retired bytes/count, ready bytes, and oldest
   retirement age. Add counters for reclaimed bytes/count and blocked rotation.
   Keep metrics off per-element reads and append existing counter indices.

   Run allocation-lifetime checks under ASan, `just test`, `just clippy`, and
   `just fmt-check` after implementation. Use model tests or isolated Miri tests
   for the primitive; passing ASan alone does not establish concurrent soundness.
   Measure `just perf-local`, concurrent API/checkpoint reads, and repeated registry growth.
   Track atomic contention, copying, retained memory, and maintenance latency.

The next implementation step is the epoch primitive and its concurrency tests.
Then add reader guards and adapt the existing `RetiredColumns` paths for both registries.
Enable reclamation only after their publication and lifetime protocol is in place.
