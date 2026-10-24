import LeanBlsSimd.Portable.Msm.BatchPrepare
import LeanBlsSimd.Portable.Msm.BatchFinish

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Msm.Batch
open BatchedRefines
set_option maxRecDepth 4096

private theorem pick_inverse [RuntimeFeatures] (values : ℕ → ChainField) (j : Usize)
    (prefixes : alloc.vec.Vec portable.fp.Fp)
    (hn : ∀ l < j.val+1, values l ≠ 0)
    (hpref : 4 ≤ j.val → prefixes.val[j.val-4]? =
      some (Kzg.fpEncode (chainPrefix values (j.val-4))).l) :
    (do if j < portable.msm.pairs.CHAINS then
          (inverseArray values (j.val+1)).index_usize (chainIndex j)
        else do
          let f ← (inverseArray values (j.val+1)).index_usize (chainIndex j)
          let p ← j-portable.msm.pairs.CHAINS
          let prior ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice portable.fp.Fp) prefixes p
          portable.fp.Fp.mul f prior) = ok (Kzg.fpEncode ((values j.val)⁻¹ : ChainField)).l := by
  have hk : (chainIndex j).val < 4 := by simp only [chainIndex,UScalar.ofNatCore_val_eq]; omega
  have hkey : (⟨(chainIndex j).val,hk⟩ : Fin 4) = chainKey j.val := by rfl
  have hr := inverseArray_index values (j.val+1) (chainIndex j) hk
  rw [hkey] at hr
  have hinv := recovered_inverse values j.val hn
  simp only [portable.msm.pairs.CHAINS,UScalar.lt_equiv,show (4#usize).val = 4 from rfl]
  by_cases hsmall : j.val < 4
  · rw [if_pos hsmall,hr]
    rw [if_pos hsmall,mul_one] at hinv
    exact congrArg (fun x : ChainField => ok (Kzg.fpEncode x).l) hinv
  · rw [if_neg hsmall,hr]
    simp only [bind_tc_ok]
    rw [sub_ok j 4#usize (by change 4 ≤ j.val; omega)]
    simp only [bind_tc_ok, show (4#usize).val = 4 from rfl]
    have hp := hpref (by omega)
    have hpi := index_of_some prefixes
      (UScalar.ofNatCore (j.val-4) (by have := j.hBounds; omega))
      (Kzg.fpEncode (chainPrefix values (j.val-4))).l hp
    rw [hpi]
    simp only [bind_tc_ok]
    have hm : portable.fp.Fp.mul
        (Kzg.fpEncode ((chainValues values (j.val+1) (chainKey j.val))⁻¹ : ChainField)).l
        (Kzg.fpEncode (chainPrefix values (j.val-4))).l =
        ok (Kzg.fpEncode ((chainValues values (j.val+1) (chainKey j.val))⁻¹ *
          chainPrefix values (j.val-4))).l := Fp.mul_encoded _ _
    rw [hm]
    rw [if_neg hsmall] at hinv
    exact congrArg (fun x : ChainField => ok (Kzg.fpEncode x).l) hinv

theorem unwind_step [RuntimeFeatures]
    (a b out : alloc.vec.Vec U32) (dx prefixes : alloc.vec.Vec portable.fp.Fp)
    (store : portable.msm.store.PointStore) (i j : Usize) (values : ℕ → ChainField)
    (hij : i.val = j.val+1) (hn : ∀ l < j.val+1, values l ≠ 0)
    (hdx : dx.val[j.val]? = some (Kzg.fpEncode (values j.val)).l)
    (hpref : 4 ≤ j.val → prefixes.val[j.val-4]? =
      some (Kzg.fpEncode (chainPrefix values (j.val-4))).l)
    (ra rb output : U32) (xa ya xb yb : ChainField)
    (ha : a.val[j.val]? = some ra) (hb : b.val[j.val]? = some rb)
    (ho : out.val[j.val]? = some output)
    (hsa : store.signed ra = ok ((Kzg.fpEncode xa).l,(Kzg.fpEncode ya).l))
    (hsb : store.signed rb = ok ((Kzg.fpEncode xb).l,(Kzg.fpEncode yb).l))
    (hbound : output.val < store.points.val.length) :
    portable.msm.pairs.BatchedAdds.run_loop0_loop0.body a b out dx prefixes store i
        (inverseArray values (j.val+1)) =
      ok (cont (Store.write store output.val
        (finishValues xa ya xb yb (values j.val)⁻¹).1
        (finishValues xa ya xb yb (values j.val)⁻¹).2,j,inverseArray values j.val)) := by
  have hi : (0#usize).val < i.val := by change 0 < i.val; omega
  have hsub : i-1#usize = ok j := by
    rw [sub_ok _ _ (by change 1 ≤ i.val; omega)]
    congr 1
    apply UScalar.eq_of_val_eq
    simp only [UScalar.ofNatCore_val_eq]
    change i.val-1 = j.val
    omega
  have hk : (chainIndex j).val = j.val%4 := by simp only [chainIndex,UScalar.ofNatCore_val_eq]
  have hklt : (chainIndex j).val < 4 := by rw [hk]; omega
  have hkey : (⟨(chainIndex j).val,hklt⟩ : Fin 4) = chainKey j.val := by rfl
  have hr := inverseArray_index values (j.val+1) (chainIndex j) hklt
  rw [hkey] at hr
  have hm : portable.fp.Fp.mul
      (Kzg.fpEncode ((chainValues values (j.val+1) (chainKey j.val))⁻¹ : ChainField)).l
      (Kzg.fpEncode (values j.val)).l =
      ok (Kzg.fpEncode ((chainValues values (j.val+1) (chainKey j.val))⁻¹ * values j.val)).l :=
    Fp.mul_encoded _ _
  have hu := inverseArray_update values j.val (chainIndex j) hk hn
  have hf := finish_encoded ⟨a,b,out,dx,prefixes⟩ store j ra rb output xa ya xb yb
    (values j.val)⁻¹ ha hb ho hsa hsb hbound
  have hiz : i > 0#usize := by simpa only [UScalar.lt_equiv] using hi
  have hrem : j % portable.msm.pairs.CHAINS = ok (chainIndex j) := by
    rw [portable.msm.pairs.CHAINS,rem_four]
  simp only [portable.msm.pairs.BatchedAdds.run_loop0_loop0.body,hiz,if_true,
    hsub,bind_tc_ok,hrem]
  rw [pick_inverse values j prefixes hn hpref]
  simp only [bind_tc_ok,hr,index_of_some _ _ _ hdx,hm,hu,hf]

end LeanBlsSimd.Portable.Msm.Batch
