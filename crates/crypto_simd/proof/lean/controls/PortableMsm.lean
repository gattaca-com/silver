import LeanBlsSimd.Portable.Msm.BatchRun
import LeanBlsSimd.Portable.Msm.FillReady
import LeanBlsSimd.Portable.Msm.StoreLifecycle

open Aeneas Aeneas.Std Result
open silver_crypto_simd

namespace LeanBlsSimd.Portable.Msm.Controls

private def store : portable.msm.store.PointStore :=
  ⟨⟨[Fp.pairEncode 3 5, Fp.pairEncode 3 7, Fp.pairEncode 0 0], by scalar_tac⟩, 2#usize⟩

private def adds : portable.msm.pairs.BatchedAdds :=
  ⟨⟨[0#u32], by scalar_tac⟩,⟨[1#u32], by scalar_tac⟩,⟨[2#u32], by scalar_tac⟩,
    alloc.vec.Vec.new _,alloc.vec.Vec.new _⟩

theorem negated_reference_clears_index :
    store.x 2147483649#u32 = ok (Kzg.fpEncode 3).l :=
  Store.x_refines store _ 3 7 (by rfl)

theorem negated_reference_changes_y :
    store.signed 2147483649#u32 = ok ((Kzg.fpEncode 3).l,(Kzg.fpEncode (-7)).l) := by
  simpa only [show 2^31 ≤ (2147483649#u32).val from by decide, if_true] using
    Store.signed_refines store 2147483649#u32 3 7 (by rfl)

theorem omitted_negation_rejected :
    store.signed 2147483649#u32 ≠ ok ((Kzg.fpEncode 3).l,(Kzg.fpEncode 7).l) := by
  rw [negated_reference_changes_y]
  intro h
  have he := congrArg (fun p => Kzg.fpRead ⟨p.2⟩) (Result.ok.inj h)
  change Kzg.fpRead (Kzg.fpEncode (-7)) = Kzg.fpRead (Kzg.fpEncode 7) at he
  simp only [Kzg.fpRead_fpEncode] at he
  have hn : (-7 : EthLib.Cryptography.Bls.Fp) ≠ 7 := by decide +kernel
  exact hn he

theorem output_write_preserves_original :
    (Store.write store 2 9 11).points.val[0]? = store.points.val[0]? :=
  Store.write_other store 2 0 9 11 (by decide)

theorem equal_x_rejects_round [RuntimeFeatures] :
    ∃ next, adds.run store = ok (false,next,store) := by
  obtain ⟨next,h,_,_,_⟩ := Batch.run_rejects_first adds store 0#u32 1#u32 3 5 7 (by rfl) (by rfl)
    (by rfl) (by rfl)
  exact ⟨next,h⟩

theorem equal_x_success_rejected [RuntimeFeatures]
    (next : portable.msm.pairs.BatchedAdds) (out : portable.msm.store.PointStore) :
    adds.run store ≠ ok (true,next,out) := by
  obtain ⟨next',h⟩ := equal_x_rejects_round
  rw [h]
  intro he
  have hf := congrArg Prod.fst (Result.ok.inj he)
  cases hf

private def buckets : portable.msm.buckets.Buckets :=
  ⟨4#usize,1#usize,alloc.vec.Vec.new _,alloc.vec.Vec.new _,⟨[0#u32],by scalar_tac⟩⟩

theorem dropped_count_rejected : buckets.count 0#usize 1#usize ≠ ok buckets := by
  obtain ⟨i,hi,hiv⟩ := BucketsRefines.list_refines (Buckets.toLane buckets)
    0#usize 1#usize (by decide) (by decide) (by decide) (by decide) (by decide)
  have hz : i = 0#usize := by
    apply UScalar.eq_of_val_eq
    simpa only [BucketsRefines.listIndex, buckets, Buckets.toLane] using hiv
  rw [hz] at hi
  have hc := BucketsRefines.count_at (Buckets.toLane buckets) 0#usize 1#usize 0#usize
    (by decide) hi (by decide) (by decide)
  rw [Buckets.count_eq, hc]
  simp only [bind_tc_ok]
  intro h
  have hl := congrArg (fun b : portable.msm.buckets.Buckets => b.lens.val.map UScalar.val)
    (Result.ok.inj h)
  change [1] = [0] at hl
  cases hl

theorem chunk_counters_fit : 2*32*portable.msm.CHUNK.val < 2^31 ∧
    (2+32)*portable.msm.CHUNK.val < 2^31 :=
  Buckets.chunk_reference_bounds _ (Nat.le_refl _)

private def differences (i : ℕ) : Batch.ChainField := (i+2 : ℕ)

private def inputRefs (r : U32) : alloc.vec.Vec U32 :=
  ⟨List.replicate 5 r, by scalar_tac⟩

private def zeros : alloc.vec.Vec portable.fp.Fp :=
  ⟨List.replicate 5 (Kzg.fpEncode 0).l, by scalar_tac⟩

private def differenceStore : portable.msm.store.PointStore :=
  ⟨⟨[Fp.pairEncode 0 1,Fp.pairEncode 6 1,Fp.pairEncode 0 0],by scalar_tac⟩,2#usize⟩

theorem fifth_job_stores_chain_prefix [RuntimeFeatures] :
    ∃ next, portable.msm.pairs.BatchedAdds.run_loop0.body
        (inputRefs 0#u32) (inputRefs 1#u32) (inputRefs 2#u32) differenceStore 5#usize
        zeros zeros (Batch.chainArray differences 4) 4#usize =
      ok (ControlFlow.cont (zeros.set 4#usize (Kzg.fpEncode 6).l,
        zeros.set 4#usize (Kzg.fpEncode 12).l,Batch.chainArray differences 5,next)) := by
  obtain ⟨next,_,he⟩ := Batch.prepare_step (inputRefs 0#u32) (inputRefs 1#u32) (inputRefs 2#u32)
    zeros zeros differenceStore 5#usize 4#usize differences 0#u32 1#u32 0 1 6 1
    (by decide) (by rfl) (by rfl) (by rfl) (by rfl) (by decide +kernel)
    (by decide +kernel) (by decide) (by decide)
  exact ⟨next,he⟩

theorem missing_fifth_prefix_rejected [RuntimeFeatures]
    (dx : alloc.vec.Vec portable.fp.Fp) (products : Array portable.fp.Fp 4#usize) (next : Usize) :
    portable.msm.pairs.BatchedAdds.run_loop0.body
        (inputRefs 0#u32) (inputRefs 1#u32) (inputRefs 2#u32) differenceStore 5#usize
        zeros zeros (Batch.chainArray differences 4) 4#usize ≠
      ok (ControlFlow.cont (dx,zeros,products,next)) := by
  obtain ⟨actual,he⟩ := fifth_job_stores_chain_prefix
  rw [he]
  intro h
  have hp := congrArg (fun t => t.2.1.val[4]?) (ControlFlow.cont.inj (Result.ok.inj h))
  change some (Kzg.fpEncode 12).l = some (Kzg.fpEncode 0).l at hp
  have hf := congrArg (fun raw => Kzg.fpRead ⟨raw⟩) (Option.some.inj hp)
  change Kzg.fpRead (Kzg.fpEncode 12) = Kzg.fpRead (Kzg.fpEncode 0) at hf
  simp only [Kzg.fpRead_fpEncode] at hf
  exact (by decide : (12 : EthLib.Cryptography.Bls.Fp) ≠ 0) hf

private def lateStore : portable.msm.store.PointStore :=
  ⟨⟨[Fp.pairEncode 0 1,Fp.pairEncode 6 1,Fp.pairEncode 0 0,Fp.pairEncode 0 0],
    by scalar_tac⟩,2#usize⟩

private def lateAdds : portable.msm.pairs.BatchedAdds :=
  ⟨⟨[0#u32,0#u32],by scalar_tac⟩,⟨[1#u32,0#u32],by scalar_tac⟩,
    ⟨[2#u32,3#u32],by scalar_tac⟩,alloc.vec.Vec.new _,alloc.vec.Vec.new _⟩

theorem later_equal_x_rejects [RuntimeFeatures] :
    ∃ next, lateAdds.run lateStore = ok (false,next,lateStore) := by
  let values : ℕ → Batch.ChainField := fun i => if i = 0 then 6 else 0
  have hi : Batch.Inputs lateAdds.a lateAdds.b lateStore values 2 := by
    intro j hj
    interval_cases j
    · exact ⟨0#u32,1#u32,0,1,6,1,rfl,rfl,rfl,rfl,by decide +kernel⟩
    · exact ⟨0#u32,0#u32,0,1,0,1,rfl,rfl,rfl,rfl,by decide +kernel⟩
  obtain ⟨next,h,_,_,_⟩ := Batch.run_rejects_at lateAdds lateStore values 1#usize
    (by decide) hi (by intro j hj; change j < 1 at hj; interval_cases j; decide +kernel)
    (by rfl)
  exact ⟨next,h⟩

theorem later_equal_x_success_rejected [RuntimeFeatures]
    (next : portable.msm.pairs.BatchedAdds) (out : portable.msm.store.PointStore) :
    lateAdds.run lateStore ≠ ok (true,next,out) := by
  obtain ⟨next',he⟩ := later_equal_x_rejects
  rw [he]
  intro h
  have hf := congrArg Prod.fst (Result.ok.inj h)
  cases hf

private def selfWriteJobs (_ : ℕ) : QueueRefines.Job := ⟨0#u32,1#u32,0#u32⟩

private def selfWriteCoords (i : ℕ) : Batch.ChainField × Batch.ChainField :=
  if i = 0 then (0,1) else (6,1)

private def selfWriteAdds : portable.msm.pairs.BatchedAdds :=
  ⟨⟨[0#u32],by scalar_tac⟩,⟨[1#u32],by scalar_tac⟩,⟨[0#u32],by scalar_tac⟩,
    alloc.vec.Vec.new _,alloc.vec.Vec.new _⟩

theorem overwriting_own_input_succeeds [RuntimeFeatures] :
    ∃ next, selfWriteAdds.run lateStore = ok (true,next,Store.write lateStore 0 (-6) (-1)) := by
  have hstate : Batch.ExecutionState lateStore selfWriteJobs selfWriteCoords 1 := by
    intro j hj
    interval_cases j
    exact ⟨rfl,rfl,by decide⟩
  have hind : Batch.ReverseIndependent selfWriteJobs 1 := by
    intro j hj k hk
    omega
  have hnz : ∀ j < 1, Batch.differences selfWriteJobs selfWriteCoords j ≠ 0 := by
    intro j hj
    interval_cases j
    decide +kernel
  obtain ⟨next,he,_,_,_⟩ := Batch.run_success selfWriteAdds lateStore selfWriteJobs selfWriteCoords
    (by intro j hj; change j < 1 at hj; interval_cases j; rfl)
    (by intro j hj; change j < 1 at hj; interval_cases j; rfl)
    (by intro j hj; change j < 1 at hj; interval_cases j; rfl) hstate hind hnz
  have hout : Batch.jobResult selfWriteJobs selfWriteCoords 0 = (-6,-1) := by
    simp [Batch.jobResult,Batch.signedPair,Batch.finishValues,selfWriteJobs,selfWriteCoords]
  refine ⟨next,?_⟩
  simpa only [show selfWriteAdds.a.val.length = 1 from rfl,Batch.execute,hout] using he

set_option exponentiation.threshold 512 in
theorem omitted_reverse_write_rejected [RuntimeFeatures]
    (next : portable.msm.pairs.BatchedAdds) : selfWriteAdds.run lateStore ≠ ok (true,next,lateStore) := by
  obtain ⟨actual,he⟩ := overwriting_own_input_succeeds
  rw [he]
  intro h
  have hs := congrArg (fun t => t.2.2.points.val[0]?) (Result.ok.inj h)
  change some (Fp.pairEncode (-6) (-1)) = some (Fp.pairEncode 0 1) at hs
  have hx := congrArg (fun row => Kzg.fpRead ⟨row.val[0]!⟩) (Option.some.inj hs)
  change Kzg.fpRead (Kzg.fpEncode (-6)) = Kzg.fpRead (Kzg.fpEncode 0) at hx
  simp only [Kzg.fpRead_fpEncode] at hx
  exact (by decide +kernel : (-6 : EthLib.Cryptography.Bls.Fp) ≠ 0) hx

#print axioms Batch.execute_loop
#print axioms Batch.run_cases
#print axioms Batch.run_rejects_at
#print axioms Batch.prepare_all
#print axioms Buckets.fill_eq
#print axioms Buckets.fill127_ready
#print axioms Store.signed_refines
#print axioms Store.reset_refines
#print axioms Batch.run_rejects_first
#print axioms Batch.prepare_step
#print axioms Batch.unwind_step
#print axioms Batch.finishValues_point

end LeanBlsSimd.Portable.Msm.Controls
