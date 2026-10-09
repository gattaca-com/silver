import LeanBlsSimd.Refines.Basic

/-! The generated constants, as the model's constants under the conversions of `Refines.Basic`. -/

open Aeneas Aeneas.Std Result
open silver_bls_simd

namespace LeanBlsSimd

theorem LIMBS_refines : constants.LIMBS = 8#usize := by rw [constants.LIMBS]

theorem LIMB_BITS_refines : constants.LIMB_BITS = 52#u32 := by rw [constants.LIMB_BITS]

theorem MASK52_refines : constants.MASK52 = ok (toU64 (.ofNat MASK52)) := by
  rw [constants.MASK52, constants.LIMB_BITS]; rfl

theorem P_refines : constants.P = toArray toU64 (Limbs.ofList P) := by rw [constants.P]; rfl

theorem P_U64_refines : constants.P_U64 = toArray toU64 DecompressG2.P_U64v := by
  rw [constants.P_U64]; rfl

theorem P_INV52_refines : constants.P_INV52 = toU64 (.ofNat P_INV52) := by
  rw [constants.P_INV52]; rfl

theorem R_MOD_P_refines : constants.R_MOD_P = toArray toU64 (Limbs.ofList R_MOD_P) := by
  rw [constants.R_MOD_P]; rfl

theorem R2_MOD_P_refines : constants.R2_MOD_P = toArray toU64 (Limbs.ofList R2_MOD_P) := by
  rw [constants.R2_MOD_P]; rfl

theorem TWO_POW_384_MOD_P_refines :
    constants.TWO_POW_384_MOD_P = toArray toU64 (Limbs.ofList TWO_POW_384_MOD_P) := by
  rw [constants.TWO_POW_384_MOD_P]; rfl

theorem ONE_PLAIN_refines : constants.ONE_PLAIN = toArray toU64 (Limbs.ofList ONE_PLAIN) := by
  rw [constants.ONE_PLAIN]; rfl

theorem FOUR_MONT_refines : constants.FOUR_MONT = toArray toU64 (Limbs.ofList FOUR_MONT) := by
  rw [constants.FOUR_MONT]; rfl

theorem HALF_P_MINUS_1_refines :
    constants.HALF_P_MINUS_1 = toArray toU64 (Limbs.ofList HALF_P_MINUS_1) := by
  rw [constants.HALF_P_MINUS_1]; rfl

theorem PSI_X_MONT_refines : constants.PSI_X_MONT = toArray toU64 (Limbs.ofList PSI_X_MONT) := by
  rw [constants.PSI_X_MONT]; rfl

theorem PSI_Y_MONT_refines :
    constants.PSI_Y_MONT =
      toArray (toArray toU64) #v[Limbs.ofList PSI_Y_MONT[0]!, Limbs.ofList PSI_Y_MONT[1]!] := by
  rw [constants.PSI_Y_MONT]; rfl

theorem HALF_MONT_refines : constants.HALF_MONT = toArray toU64 (Limbs.ofList HALF_MONT) := by
  rw [constants.HALF_MONT]; rfl

theorem P_MINUS_3_OVER_4_WINDOWS_refines :
    constants.P_MINUS_3_OVER_4_WINDOWS.val.map UScalar.val = P_MINUS_3_OVER_4_WINDOWS := by
  rw [constants.P_MINUS_3_OVER_4_WINDOWS]; rfl

theorem Z_BITS_refines : constants.Z_BITS.val.map UScalar.val = Z_BITS := by
  rw [constants.Z_BITS]; rfl

theorem P_MINUS_3_OVER_4_WINDOWS_lt (w : ℕ) (hw : w < 95) :
    P_MINUS_3_OVER_4_WINDOWS[w]! < 2 ^ UScalarTy.U8.numBits := by
  rw [← P_MINUS_3_OVER_4_WINDOWS_refines, getElem!_map_val _ _ hw]
  exact UScalar.hBounds _

theorem P_MINUS_3_OVER_4_WINDOWS_index (w : Usize) (hw : w.val < 95) :
    Array.index_usize constants.P_MINUS_3_OVER_4_WINDOWS w =
      ok (UScalar.ofNatCore P_MINUS_3_OVER_4_WINDOWS[w.val]!
        (P_MINUS_3_OVER_4_WINDOWS_lt _ hw)) := by
  rw [index_usize_eq _ _ hw]
  congr 1
  apply UScalar.eq_of_val_eq
  simp only [UScalar.ofNatCore_val_eq]
  rw [← P_MINUS_3_OVER_4_WINDOWS_refines, getElem!_map_val _ _ hw]

theorem Z_BITS_lt (k : ℕ) (hk : k < 6) : Z_BITS[k]! < 2 ^ UScalarTy.U32.numBits := by
  rw [← Z_BITS_refines, getElem!_map_val _ _ hk]
  exact UScalar.hBounds _

theorem Z_BITS_index (k : Usize) (hk : k.val < 6) :
    Array.index_usize constants.Z_BITS k =
      ok (UScalar.ofNatCore Z_BITS[k.val]! (Z_BITS_lt _ hk)) := by
  rw [index_usize_eq _ _ hk]
  congr 1
  apply UScalar.eq_of_val_eq
  simp only [UScalar.ofNatCore_val_eq]
  rw [← Z_BITS_refines, getElem!_map_val _ _ hk]

theorem LANES_refines : fp8.LANES = 8#usize := by rw [fp8.LANES]

theorem U64_MAX_refines : core.num.U64.MAX = toU64 0xffffffffffffffff := rfl

end LeanBlsSimd
