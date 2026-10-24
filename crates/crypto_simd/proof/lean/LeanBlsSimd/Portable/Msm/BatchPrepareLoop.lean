import LeanBlsSimd.Portable.Msm.BatchPrepare

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd

namespace LeanBlsSimd.Portable.Msm.Batch

/-- Differences and prefixes have been written only for the processed jobs. -/
def Prepared (dx prefixes : alloc.vec.Vec portable.fp.Fp) (values : ℕ → ChainField)
    (processed : ℕ) : Prop :=
  ∀ j < processed, dx.val[j]? = some (Kzg.fpEncode (values j)).l ∧
    prefixes.val[j]? = some (Kzg.fpEncode (chainPrefix values j)).l

/-- Both references name initialized coordinates; signs do not change their x values. -/
def Inputs (a b : alloc.vec.Vec U32) (store : portable.msm.store.PointStore)
    (values : ℕ → ChainField) (n : ℕ) : Prop :=
  ∀ j < n, ∃ (ra rb : U32) (xa ya xb yb : ChainField),
    a.val[j]? = some ra ∧ b.val[j]? = some rb ∧
    Store.Holds store (ra.val % 2^31) xa ya ∧
    Store.Holds store (rb.val % 2^31) xb yb ∧ values j = xb-xa

theorem Prepared.step (dx prefixes : alloc.vec.Vec portable.fp.Fp)
    (values : ℕ → ChainField) (i : Usize)
    (h : Prepared dx prefixes values i.val)
    (hdx : i.val < dx.val.length) (hpref : i.val < prefixes.val.length) :
    Prepared (dx.set i (Kzg.fpEncode (values i.val)).l)
      (prefixes.set i (Kzg.fpEncode (chainPrefix values i.val)).l) values (i.val+1) := by
  intro j hj
  by_cases he : i.val = j
  · subst j
    exact ⟨List.getElem?_set_self hdx,List.getElem?_set_self hpref⟩
  · simp only [alloc.vec.Vec.set,List.getElem?_set_ne he]
    exact h j (by omega)

/-- Traverse any nonzero prefix while retaining the actual continuation of the generated loop. -/
theorem prepare_prefix [RuntimeFeatures]
    (a b out : alloc.vec.Vec U32) (store : portable.msm.store.PointStore)
    (n limit i : Usize) (values : ℕ → ChainField)
    (dx prefixes : alloc.vec.Vec portable.fp.Fp)
    (hi : i.val ≤ limit.val) (hl : limit.val ≤ n.val)
    (hinputs : Inputs a b store values n.val)
    (hnz : ∀ j < limit.val, values j ≠ 0)
    (hprep : Prepared dx prefixes values i.val)
    (hdx : n.val ≤ dx.val.length) (hpref : n.val ≤ prefixes.val.length) :
    ∃ finalDx finalPrefixes,
      Prepared finalDx finalPrefixes values limit.val ∧
      finalDx.val.length = dx.val.length ∧ finalPrefixes.val.length = prefixes.val.length ∧
      portable.msm.pairs.BatchedAdds.run_loop0 a b out dx prefixes store n
        (chainArray values i.val) i =
      portable.msm.pairs.BatchedAdds.run_loop0 a b out finalDx finalPrefixes store n
        (chainArray values limit.val) limit := by
  induction hr : limit.val-i.val generalizing i dx prefixes with
  | zero =>
    have he : i = limit := UScalar.eq_of_val_eq (by omega)
    subst i
    exact ⟨dx,prefixes,hprep,rfl,rfl,rfl⟩
  | succ remaining ih =>
    have hil : i.val < limit.val := by omega
    have hin : i.val < n.val := by omega
    obtain ⟨ra,rb,xa,ya,xb,yb,ha,hb,hsa,hsb,hdiff⟩ := hinputs i.val hin
    obtain ⟨next,hnext,hstep⟩ := prepare_step a b out dx prefixes store n i values
      ra rb xa ya xb yb hin ha hb hsa hsb hdiff (hnz _ hil) (by omega) (by omega)
    let dx1 := dx.set i (Kzg.fpEncode (values i.val)).l
    let prefixes1 := prefixes.set i (Kzg.fpEncode (chainPrefix values i.val)).l
    have hp1 : Prepared dx1 prefixes1 values next.val := by
      rw [hnext]
      exact Prepared.step dx prefixes values i hprep (by omega) (by omega)
    obtain ⟨finalDx,finalPrefixes,hpf,hdf,hprf,heq⟩ := ih next dx1 prefixes1
      (by omega) hp1 (by simpa [dx1,alloc.vec.Vec.set] using hdx)
      (by simpa [prefixes1,alloc.vec.Vec.set] using hpref) (by omega)
    refine ⟨finalDx,finalPrefixes,hpf,?_,?_,?_⟩
    · simpa [dx1,alloc.vec.Vec.set] using hdf
    · simpa [prefixes1,alloc.vec.Vec.set] using hprf
    · have he : portable.msm.pairs.BatchedAdds.run_loop0 a b out dx prefixes store n
          (chainArray values i.val) i =
        portable.msm.pairs.BatchedAdds.run_loop0 a b out dx1 prefixes1 store n
          (chainArray values next.val) next := by
        unfold portable.msm.pairs.BatchedAdds.run_loop0
        rw [loop.eq_1]
        simp only [hstep,hnext]
        rfl
      exact he.trans heq

/-- A later equal-x job rejects the whole batch without changing the point store. -/
theorem prepare_rejects_at [RuntimeFeatures]
    (a b out : alloc.vec.Vec U32) (store : portable.msm.store.PointStore)
    (n stop : Usize) (values : ℕ → ChainField)
    (dx prefixes : alloc.vec.Vec portable.fp.Fp)
    (hstop : stop.val < n.val) (hinputs : Inputs a b store values n.val)
    (hnz : ∀ j < stop.val, values j ≠ 0) (hzero : values stop.val = 0)
    (hdx : n.val ≤ dx.val.length) (hpref : n.val ≤ prefixes.val.length) :
    ∃ finalDx finalPrefixes,
      portable.msm.pairs.BatchedAdds.run_loop0 a b out dx prefixes store n
        (chainArray values 0) 0#usize = ok (false,finalDx,finalPrefixes,store) := by
  obtain ⟨finalDx,finalPrefixes,_,_,_,heq⟩ := prepare_prefix a b out store n stop 0#usize
    values dx prefixes (by simp) (by omega) hinputs hnz (by intro j hj; change j < 0 at hj; omega)
    hdx hpref
  obtain ⟨ra,rb,xa,ya,xb,yb,ha,hb,hsa,hsb,hdiff⟩ := hinputs stop.val hstop
  have hsame : xb = xa := sub_eq_zero.mp (hdiff.symm.trans hzero)
  subst xb
  refine ⟨finalDx,finalPrefixes,heq.trans ?_⟩
  exact equal_x_rejects_loop a b out finalDx finalPrefixes store n stop
    (chainArray values stop.val) ra rb xa ya yb hstop ha hb hsa hsb

/-- Successful preparation passes the encoded chain inverses to the actual reverse loop. -/
theorem prepare_all [RuntimeFeatures]
    (a b out : alloc.vec.Vec U32) (store : portable.msm.store.PointStore)
    (n : Usize) (values : ℕ → ChainField) (dx prefixes : alloc.vec.Vec portable.fp.Fp)
    (hinputs : Inputs a b store values n.val) (hnz : ∀ j < n.val, values j ≠ 0)
    (hdx : n.val ≤ dx.val.length) (hpref : n.val ≤ prefixes.val.length) :
    ∃ finalDx finalPrefixes, Prepared finalDx finalPrefixes values n.val ∧
      finalDx.val.length = dx.val.length ∧ finalPrefixes.val.length = prefixes.val.length ∧
      portable.msm.pairs.BatchedAdds.run_loop0 a b out dx prefixes store n
        (chainArray values 0) 0#usize =
      (do let result ← portable.msm.pairs.BatchedAdds.run_loop0_loop0 a b out finalDx
            finalPrefixes store n (inverseArray values n.val)
          ok (true,finalDx,finalPrefixes,result)) := by
  obtain ⟨finalDx,finalPrefixes,hp,hd,hpr,heq⟩ := prepare_prefix a b out store n n 0#usize
    values dx prefixes (by simp) (by omega) hinputs hnz
    (by intro j hj; change j < 0 at hj; omega) hdx hpref
  refine ⟨finalDx,finalPrefixes,hp,hd,hpr,heq.trans ?_⟩
  rw [portable.msm.pairs.BatchedAdds.run_loop0,loop.eq_1]
  simp only [portable.msm.pairs.BatchedAdds.run_loop0.body,lt_self_iff_false,if_false,
    batch_inverse_chains values n.val hnz,bind_tc_ok]
  cases h : portable.msm.pairs.BatchedAdds.run_loop0_loop0 a b out finalDx
    finalPrefixes store n (inverseArray values n.val) <;> rfl

theorem run_rejects_at [RuntimeFeatures] (adds : portable.msm.pairs.BatchedAdds)
    (store : portable.msm.store.PointStore) (values : ℕ → ChainField) (stop : Usize)
    (hstop : stop.val < adds.a.val.length) (hinputs : Inputs adds.a adds.b store values adds.a.val.length)
    (hnz : ∀ j < stop.val, values j ≠ 0) (hzero : values stop.val = 0) :
    ∃ next, adds.run store = ok (false,next,store) ∧
      next.a = adds.a ∧ next.b = adds.b ∧ next.out = adds.out := by
  let n := alloc.vec.Vec.len adds.a
  let dx := BatchedRefines.resizeVec adds.dx n portable.fp.Fp.ZERO
  let prefixes := BatchedRefines.resizeVec adds.prefix n portable.fp.Fp.ZERO
  have hclone : portable.fp.Fp.Insts.CoreCloneClone.clone portable.fp.Fp.ZERO =
      ok portable.fp.Fp.ZERO := rfl
  have hdx : n.val ≤ dx.val.length := by simp [dx,BatchedRefines.resizeVec]
  have hpref : n.val ≤ prefixes.val.length := by simp [prefixes,BatchedRefines.resizeVec]
  obtain ⟨finalDx,finalPrefixes,hr⟩ := prepare_rejects_at adds.a adds.b adds.out store n stop
    values dx prefixes (by simpa [n] using hstop) (by simpa [n] using hinputs) hnz hzero hdx hpref
  refine ⟨{adds with dx := finalDx, «prefix» := finalPrefixes},?_,rfl,rfl,rfl⟩
  rw [chainArray_zero] at hr
  simp only [portable.msm.pairs.BatchedAdds.run,
    BatchedRefines.resizeVec_refines _ _ portable.fp.Fp.ZERO portable.fp.Fp.Insts.CoreCloneClone hclone,bind_tc_ok]
  change (do
    let result ← portable.msm.pairs.BatchedAdds.run_loop0 adds.a adds.b adds.out
      dx prefixes store n (Array.repeat 4#usize portable.constants.ONE) 0#usize
    ok (result.1,{adds with dx := result.2.1, «prefix» := result.2.2.1},result.2.2.2)) = _
  rw [hr]
  rfl

end LeanBlsSimd.Portable.Msm.Batch
