import LeanBlsSimd.Portable.Msm.BatchExecute

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd

namespace LeanBlsSimd.Portable.Msm.Batch
open QueueRefines

theorem ExecutionState.inputs (adds : portable.msm.pairs.BatchedAdds)
    (store : portable.msm.store.PointStore) (jobs : ℕ → Job)
    (coords : ℕ → ChainField × ChainField) (n : ℕ)
    (ha : ∀ j < n, adds.a.val[j]? = some (jobs j).first)
    (hb : ∀ j < n, adds.b.val[j]? = some (jobs j).second)
    (hs : ExecutionState store jobs coords n) :
    Inputs adds.a adds.b store (differences jobs coords) n := by
  intro j hj
  obtain ⟨hsa,hsb,_⟩ := hs j hj
  exact ⟨(jobs j).first,(jobs j).second,_,_,_,_,ha j hj,hb j hj,hsa,hsb,rfl⟩

theorem run_success [RuntimeFeatures] (adds : portable.msm.pairs.BatchedAdds)
    (store : portable.msm.store.PointStore) (jobs : ℕ → Job)
    (coords : ℕ → ChainField × ChainField)
    (ha : ∀ j < adds.a.val.length, adds.a.val[j]? = some (jobs j).first)
    (hb : ∀ j < adds.a.val.length, adds.b.val[j]? = some (jobs j).second)
    (ho : ∀ j < adds.a.val.length, adds.out.val[j]? = some (jobs j).output)
    (hstate : ExecutionState store jobs coords adds.a.val.length)
    (hind : ReverseIndependent jobs adds.a.val.length)
    (hnz : ∀ j < adds.a.val.length, differences jobs coords j ≠ 0) :
    ∃ next, adds.run store = ok (true,next,execute jobs coords adds.a.val.length store) ∧
      next.a = adds.a ∧ next.b = adds.b ∧ next.out = adds.out := by
  let n := alloc.vec.Vec.len adds.a
  let dx := BatchedRefines.resizeVec adds.dx n portable.fp.Fp.ZERO
  let prefixes := BatchedRefines.resizeVec adds.prefix n portable.fp.Fp.ZERO
  have hclone : portable.fp.Fp.Insts.CoreCloneClone.clone portable.fp.Fp.ZERO =
      ok portable.fp.Fp.ZERO := rfl
  have hdx : n.val ≤ dx.val.length := by simp [dx,BatchedRefines.resizeVec]
  have hpref : n.val ≤ prefixes.val.length := by simp [prefixes,BatchedRefines.resizeVec]
  obtain ⟨finalDx,finalPrefixes,hp,_,_,hr⟩ := prepare_all adds.a adds.b adds.out store n
    (differences jobs coords) dx prefixes (ExecutionState.inputs adds store jobs coords _ ha hb hstate)
    hnz hdx hpref
  have he := execute_loop adds.a adds.b adds.out finalDx finalPrefixes jobs coords
    adds.a.val.length store n (by simp [n]) ha hb ho hstate hind hp hnz
  have hnv : n.val = adds.a.val.length := by simp [n]
  simp only [hnv] at hr
  rw [he] at hr
  simp only [bind_tc_ok] at hr
  rw [chainArray_zero] at hr
  refine ⟨{adds with dx := finalDx, «prefix» := finalPrefixes},?_,rfl,rfl,rfl⟩
  simp only [portable.msm.pairs.BatchedAdds.run,
    BatchedRefines.resizeVec_refines _ _ portable.fp.Fp.ZERO portable.fp.Fp.Insts.CoreCloneClone hclone,
    bind_tc_ok]
  change (do
    let result ← portable.msm.pairs.BatchedAdds.run_loop0 adds.a adds.b adds.out
      dx prefixes store n (Array.repeat 4#usize portable.constants.ONE) 0#usize
    ok (result.1,{adds with dx := result.2.1, «prefix» := result.2.2.1},result.2.2.2)) = _
  rw [hr]
  rfl

/-- Every well-formed batch either rejects without store writes or executes all queued additions. -/
theorem run_cases [RuntimeFeatures] (adds : portable.msm.pairs.BatchedAdds)
    (store : portable.msm.store.PointStore) (jobs : ℕ → Job)
    (coords : ℕ → ChainField × ChainField)
    (ha : ∀ j < adds.a.val.length, adds.a.val[j]? = some (jobs j).first)
    (hb : ∀ j < adds.a.val.length, adds.b.val[j]? = some (jobs j).second)
    (ho : ∀ j < adds.a.val.length, adds.out.val[j]? = some (jobs j).output)
    (hstate : ExecutionState store jobs coords adds.a.val.length)
    (hind : ReverseIndependent jobs adds.a.val.length) :
    ∃ next, next.a = adds.a ∧ next.b = adds.b ∧ next.out = adds.out ∧
      (adds.run store = ok (false,next,store) ∨
        ((∀ j < adds.a.val.length, differences jobs coords j ≠ 0) ∧
          adds.run store = ok (true,next,execute jobs coords adds.a.val.length store))) := by
  classical
  by_cases hnz : ∀ j < adds.a.val.length, differences jobs coords j ≠ 0
  · obtain ⟨next,hr,ha,hb,ho⟩ := run_success adds store jobs coords ha hb ho hstate hind hnz
    exact ⟨next,ha,hb,ho,Or.inr ⟨hnz,hr⟩⟩
  · have hex : ∃ j, j < adds.a.val.length ∧ differences jobs coords j = 0 := by
      push Not at hnz
      exact hnz
    have hfirst := Nat.find_spec hex
    let stop : Usize := UScalar.ofNatCore (Nat.find hex)
      (lt_trans hfirst.1 (vec_length_bound adds.a))
    have hstop : stop.val = Nat.find hex := rfl
    have hprefix : ∀ j < stop.val, differences jobs coords j ≠ 0 := by
      intro j hj he
      have hmin := Nat.find_min' hex (show j < adds.a.val.length ∧ differences jobs coords j = 0 from
        ⟨by rw [hstop] at hj; omega,he⟩)
      rw [hstop] at hj
      omega
    obtain ⟨next,hr,ha,hb,ho⟩ := run_rejects_at adds store (differences jobs coords) stop
      hfirst.1 (ExecutionState.inputs adds store jobs coords _ ha hb hstate) hprefix hfirst.2
    exact ⟨next,ha,hb,ho,Or.inl hr⟩

end LeanBlsSimd.Portable.Msm.Batch
