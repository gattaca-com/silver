import LeanBlsSimd.Portable.Msm.ChainEncoding
import LeanBlsSimd.Portable.Msm.BatchReject

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Msm.Batch
open BatchedRefines
set_option maxRecDepth 4096

theorem index_of_some {α : Type} (v : alloc.vec.Vec α) (i : Usize) (x : α)
    (h : v.val[i.val]? = some x) :
    alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice α) v i = ok x := by
  obtain ⟨hb,he⟩ := List.getElem?_eq_some_iff.mp h
  rw [BucketsRefines.vec_index _ _ hb,he]

private theorem isZero_false (x : ChainField) (h : x ≠ 0) : Bls.Fp.isZero x = false := by
  apply Bool.eq_false_iff.mpr
  intro he
  apply h
  apply ZMod.val_injective
  simpa only [Bls.Fp.isZero,beq_iff_eq,ZMod.val_zero] using he

theorem prepare_step [RuntimeFeatures]
    (a b out : alloc.vec.Vec U32) (dx prefixes : alloc.vec.Vec portable.fp.Fp)
    (store : portable.msm.store.PointStore) (n i : Usize) (values : ℕ → ChainField)
    (ra rb : U32) (xa ya xb yb : ChainField)
    (hi : i.val < n.val) (ha : a.val[i.val]? = some ra) (hb : b.val[i.val]? = some rb)
    (hxa : Store.Holds store (ra.val % 2^31) xa ya)
    (hxb : Store.Holds store (rb.val % 2^31) xb yb)
    (hdiff : values i.val = xb-xa) (hnz : values i.val ≠ 0)
    (hdx : i.val < dx.val.length) (hpref : i.val < prefixes.val.length) :
    ∃ next : Usize, next.val = i.val+1 ∧
      portable.msm.pairs.BatchedAdds.run_loop0.body a b out store n dx prefixes
        (chainArray values i.val) i =
      ok (cont (dx.set i (Kzg.fpEncode (values i.val)).l,
        prefixes.set i (Kzg.fpEncode (chainPrefix values i.val)).l,
        chainArray values (i.val+1), next)) := by
  let k := chainIndex i
  have hk : k.val = i.val%4 := by simp only [k,chainIndex,UScalar.ofNatCore_val_eq]
  have hklt : k.val < 4 := by rw [hk]; exact Nat.mod_lt _ (by decide)
  have hkey : (⟨k.val,hklt⟩ : Fin 4) = chainKey i.val := by apply Fin.ext; exact hk
  have hinc : i.val+(1#usize).val < 2^UScalarTy.Usize.numBits := by
    have hbound := vec_length_bound dx
    change i.val+1 < _
    omega
  let next : Usize := UScalar.ofNatCore (i.val+1) hinc
  have hnext : i+1#usize = ok next := by rw [add_ok _ _ hinc]; rfl
  have hsub : portable.fp.Fp.sub (Kzg.fpEncode xb).l (Kzg.fpEncode xa).l =
      ok (Kzg.fpEncode (values i.val)).l := by
    rw [Fp.sub_encoded]
    exact congrArg (fun x : ChainField => ok (Kzg.fpEncode x).l) hdiff.symm
  have hread : (chainArray values i.val).index_usize k =
      ok (Kzg.fpEncode (chainValues values i.val (chainKey i.val))).l := by
    rw [chainArray_index _ _ _ hklt, hkey]
  have hmul : portable.fp.Fp.mul
      (Kzg.fpEncode (chainValues values i.val (chainKey i.val))).l
      (Kzg.fpEncode (values i.val)).l =
      ok (Kzg.fpEncode (chainValues values i.val (chainKey i.val) * values i.val)).l :=
    Fp.mul_encoded _ _
  have hwrite := chainArray_update values i.val k hk
  have hprefix : (chainArray values (i.val+1)).index_usize k =
      ok (Kzg.fpEncode (chainPrefix values i.val)).l := by
    rw [chainArray_index _ _ _ hklt, hkey]
    rfl
  refine ⟨next, by simp [next], ?_⟩
  simp only [portable.msm.pairs.BatchedAdds.run_loop0.body, UScalar.lt_equiv,hi,if_true,
    index_of_some _ _ _ hb,index_of_some _ _ _ ha,bind_tc_ok,
    Store.x_refines store rb xb yb hxb,Store.x_refines store ra xa ya hxa,
    hsub,Fp.is_zero_encoded,isZero_false _ hnz,Bool.false_eq_true,if_false,
    portable.msm.pairs.CHAINS,rem_four]
  simp only [k] at hread hwrite hprefix
  simp only [hread,bind_tc_ok,hmul,hwrite,hprefix,
    BucketsRefines.vec_index_mut _ _ hdx,BucketsRefines.vec_index_mut _ _ hpref,
    Function.uncurry_def,hnext]

end LeanBlsSimd.Portable.Msm.Batch
