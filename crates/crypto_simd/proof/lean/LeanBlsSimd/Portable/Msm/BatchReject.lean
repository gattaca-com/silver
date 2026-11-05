import LeanBlsSimd.Portable.Msm.Store
import LeanBlsSimd.Portable.Fp.Correct

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd

attribute [local implicit_reducible] ZMod EthLib.Cryptography.Bls.Fp.modulus UScalar.cMax UScalar.rMax U32.rMax

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
  simp only [portable.msm.pairs.BatchedAdds.run_loop0.body, UScalar.lt_equiv, hi, ite_true,
    BucketsRefines.vec_index _ _ hib, heb, Store.x_refines store rb x yb hxb, bind_ok,
    BucketsRefines.vec_index _ _ hia, hea, Store.x_refines store ra x ya hxa,
    Fp.sub_encoded, sub_self, Fp.is_zero_encoded, show EthLib.Cryptography.Bls.Fp.isZero 0 = true from rfl, ite_true]

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
  simp only [equal_x_rejects_step a b out dx prefixes store n i products ra rb x ya yb hi ha hb hxa hxb, bind_ok]

end LeanBlsSimd.Portable.Msm.Batch
