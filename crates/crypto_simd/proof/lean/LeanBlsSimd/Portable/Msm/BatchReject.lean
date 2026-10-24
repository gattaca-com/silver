import LeanBlsSimd.Portable.Msm.Store
import LeanBlsSimd.Portable.Fp.Correct

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd

namespace LeanBlsSimd.Portable.Msm.Batch

/-- Equal x coordinates end preparation without reading the inversion scratch or writing the store. -/
theorem equal_x_rejects_step [RuntimeFeatures]
    (a b out : alloc.vec.Vec U32) (dx prefixes : alloc.vec.Vec portable.fp.Fp)
    (store : portable.msm.store.PointStore) (n i : Usize)
    (products : Array portable.fp.Fp 4#usize)
    (ra rb : U32) (x ya yb : ZMod EthLib.Cryptography.Bls.Fp.modulus)
    (hi : i.val < n.val) (ha : a.val[i.val]? = some ra) (hb : b.val[i.val]? = some rb)
    (hxa : Store.Holds store (ra.val % 2^31) x ya)
    (hxb : Store.Holds store (rb.val % 2^31) x yb) :
    portable.msm.pairs.BatchedAdds.run_loop0.body a b out store n dx prefixes products i =
      ok (done (false, dx, prefixes, store)) := by
  have hia := (List.getElem?_eq_some_iff.mp ha).choose
  have hib := (List.getElem?_eq_some_iff.mp hb).choose
  have hea : a.val[i.val] = ra := by simpa only [List.getElem?_eq_getElem hia, Option.some.injEq] using ha
  have heb : b.val[i.val] = rb := by simpa only [List.getElem?_eq_getElem hib, Option.some.injEq] using hb
  simp only [portable.msm.pairs.BatchedAdds.run_loop0.body, UScalar.lt_equiv, hi, if_true,
    BucketsRefines.vec_index _ _ hib, heb, Store.x_refines store rb x yb hxb, bind_tc_ok,
    BucketsRefines.vec_index _ _ hia, hea, Store.x_refines store ra x ya hxa,
    Fp.sub_encoded, sub_self, Fp.is_zero_encoded, show EthLib.Cryptography.Bls.Fp.isZero 0 = true from rfl, if_true]

theorem equal_x_rejects_loop [RuntimeFeatures]
    (a b out : alloc.vec.Vec U32) (dx prefixes : alloc.vec.Vec portable.fp.Fp)
    (store : portable.msm.store.PointStore) (n i : Usize)
    (products : Array portable.fp.Fp 4#usize)
    (ra rb : U32) (x ya yb : ZMod EthLib.Cryptography.Bls.Fp.modulus)
    (hi : i.val < n.val) (ha : a.val[i.val]? = some ra) (hb : b.val[i.val]? = some rb)
    (hxa : Store.Holds store (ra.val % 2^31) x ya)
    (hxb : Store.Holds store (rb.val % 2^31) x yb) :
    portable.msm.pairs.BatchedAdds.run_loop0 a b out dx prefixes store n products i =
      ok (false, dx, prefixes, store) := by
  rw [portable.msm.pairs.BatchedAdds.run_loop0, loop.eq_1]
  simp only [equal_x_rejects_step a b out dx prefixes store n i products ra rb x ya yb hi ha hb hxa hxb]

theorem run_rejects_first [RuntimeFeatures] (adds : portable.msm.pairs.BatchedAdds)
    (store : portable.msm.store.PointStore)
    (ra rb : U32) (x ya yb : ZMod EthLib.Cryptography.Bls.Fp.modulus)
    (ha : adds.a.val[0]? = some ra) (hb : adds.b.val[0]? = some rb)
    (hxa : Store.Holds store (ra.val % 2^31) x ya)
    (hxb : Store.Holds store (rb.val % 2^31) x yb) :
    ∃ next, adds.run store = ok (false,next,store) ∧
      next.a = adds.a ∧ next.b = adds.b ∧ next.out = adds.out := by
  have hc : portable.fp.Fp.Insts.CoreCloneClone.clone portable.fp.Fp.ZERO = ok portable.fp.Fp.ZERO := rfl
  obtain ⟨dx, hdx, _⟩ := WP.spec_imp_exists (alloc.vec.Vec.resize_spec
    portable.fp.Fp.Insts.CoreCloneClone adds.dx (alloc.vec.Vec.len adds.a) portable.fp.Fp.ZERO hc)
  obtain ⟨prefixes, hp, _⟩ := WP.spec_imp_exists (alloc.vec.Vec.resize_spec
    portable.fp.Fp.Insts.CoreCloneClone adds.prefix (alloc.vec.Vec.len adds.a) portable.fp.Fp.ZERO hc)
  have hi : (0#usize).val < (alloc.vec.Vec.len adds.a).val := by
    simpa only [alloc.vec.Vec.len_val] using (List.getElem?_eq_some_iff.mp ha).choose
  refine ⟨{adds with dx, «prefix» := prefixes}, ?_, rfl,rfl,rfl⟩
  simp only [portable.msm.pairs.BatchedAdds.run, hdx,hp,bind_tc_ok,Function.uncurry_def,
    equal_x_rejects_loop _ _ _ _ _ _ _ _ _ ra rb x ya yb hi ha hb hxa hxb]

end LeanBlsSimd.Portable.Msm.Batch
