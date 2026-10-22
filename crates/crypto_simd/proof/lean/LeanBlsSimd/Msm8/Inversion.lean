import LeanBlsSimd.Model.Msm8
import LeanBlsSimd.Proofs.Fp8Holds
import LeanBlsSimd.Refines.Fp8

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd

open EthCryptographySpecs.Bls

namespace Fp8


theorem inverse_exponent :
    ((Fp.modulus - 3) / 4) * 2 * 2 + 1 = Fp.modulus - 2 := by decide

theorem lane_inverse_pow {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) :
    Fp8Inv (x.inverse.lane l) ∧
      decode (x.inverse.lane l) = decode (x.lane l) ^ (Fp.modulus - 2) := by
  obtain ⟨hp, he⟩ := lane_pow_p_minus_3_over_4 hx
  refine ⟨inv_mul (inv_square (inv_square hp)) hx, ?_⟩
  rw [inverse, decode_lane_mul (inv_square (inv_square hp)) hx,
    decode_lane_square (inv_square hp), decode_lane_square hp, he,
    ← pow_mul, ← pow_mul, ← pow_succ, ← Nat.mul_assoc, inverse_exponent]

theorem pow_p_minus_two_eq_inv (a : ZMod Fp.modulus) :
    a ^ (Fp.modulus - 2) = a⁻¹ := by
  by_cases ha : a = 0
  · simp [ha, show Fp.modulus - 2 ≠ 0 by decide]
  · apply (mul_right_inj' ha).mp
    rw [mul_inv_cancel₀ ha, ← pow_succ',
      show Fp.modulus - 2 + 1 = Fp.modulus - 1 by decide,
      ZMod.pow_card_sub_one_eq_one ha]

theorem Holds.inverse {x : Fp8} {l : Fin 8} {a : ZMod Fp.modulus}
    (hx : x.Holds l a) : x.inverse.Holds l a⁻¹ := by
  obtain ⟨hi, he⟩ := lane_inverse_pow hx.inv
  exact ⟨hi, by rw [he, hx.eq, pow_p_minus_two_eq_inv]⟩

theorem Holds.mul_inverse {x : Fp8} {l : Fin 8} {a : ZMod Fp.modulus}
    (hx : x.Holds l a) (ha : a ≠ 0) : (x.mul x.inverse).Holds l 1 := by
  exact (hx.mul hx.inverse).of_eq (mul_inv_cancel₀ ha)

theorem Holds.ne_zero_of_mask {x : Fp8} {l : Fin 8} {a : ZMod Fp.modulus}
    (hx : x.Holds l a) (hm : x.is_zero_mask = 0) : a ≠ 0 := by
  have hb := hx.testBit_is_zero_mask
  rw [hm, Mmask8.testBit_zero] at hb
  exact of_decide_eq_false hb.symm

end Fp8

namespace Msm8


theorem batchInverse_correct (values : Vector Fp8 4) (a : Fin 4 → ZMod Fp.modulus)
    (l : Fin 8) (hv : ∀ j : Fin 4, values[j].Holds l (a j))
    (hn : ∀ j : Fin 4, a j ≠ 0) (j : Fin 4) :
    (batchInverse values)[j].Holds l (a j)⁻¹ := by
  have hp1 := (hv 0).mul (hv 1)
  have hp2 := hp1.mul (hv 2)
  have hp3 := hp2.mul (hv 3)
  have hi3 := hp3.inverse
  have hi2 := hi3.mul (hv 3)
  have hi1 := hi2.mul (hv 2)
  fin_cases j
  · exact (hi1.mul (hv 1)).of_eq (by field_simp [hn 0, hn 1, hn 2, hn 3]; rfl)
  · exact (hi1.mul (hv 0)).of_eq (by field_simp [hn 0, hn 1, hn 2, hn 3]; rfl)
  · exact (hi2.mul hp1).of_eq (by field_simp [hn 0, hn 1, hn 2, hn 3]; rfl)
  · exact (hi3.mul hp2).of_eq (by field_simp [hn 0, hn 1, hn 2, hn 3]; rfl)

theorem batchInverse_product_nonzero (a : Fin 4 → ZMod Fp.modulus)
    (hn : ∀ j : Fin 4, a j ≠ 0) : ((a 0 * a 1) * a 2) * a 3 ≠ 0 :=
  mul_ne_zero (mul_ne_zero (mul_ne_zero (hn 0) (hn 1)) (hn 2)) (hn 3)

end Msm8
end LeanBlsSimd


namespace LeanBlsSimd

theorem Fp8.inverse_refines (self : fp8.Fp8) :
    fp8.Fp8.inverse self = ok (toFp8 (ofFp8 self).inverse) := by
  simp [fp8.Fp8.inverse, Fp8.pow_p_minus_3_over_4_refines, Fp8.square_refines,
    Fp8.mul_refines, Fp8.inverse]


private theorem batchPrefix_refines (v : Vector Fp8 4) :
    msm8.pairs.batch_inverse_loop0 (toArray toFp8 v) (toArray toFp8 v) 1#usize =
      ok (toArray toFp8
        (((v.set 1 (v[0].mul v[1])).set 2 ((v[0].mul v[1]).mul v[2])).set 3
          (((v[0].mul v[1]).mul v[2]).mul v[3]))) := by
  unfold msm8.pairs.batch_inverse_loop0
  have hs := two_pow_32_le_usize
  repeat' (rw [loop.eq_1]; simp (disch := (first | decide | (simp only [UScalar.ofNatCore_val_eq]; omega))) [
    msm8.pairs.CHAINS, msm8.pairs.batch_inverse_loop0.body, sub_ok, add_ok,
    index_usize_eq, update_eq, Fp8.mul_refines])

private theorem batchSuffix_refines (v p out : Vector Fp8 4) (inv : Fp8) :
    msm8.pairs.batch_inverse_loop1 (toArray toFp8 v) (toArray toFp8 p)
      3#usize (toFp8 inv) (toArray toFp8 out) =
      ok (toFp8 (((inv.mul v[3]).mul v[2]).mul v[1]), toArray toFp8
        (((out.set 3 (inv.mul p[2])).set 2 ((inv.mul v[3]).mul p[1])).set 1
          (((inv.mul v[3]).mul v[2]).mul p[0]))) := by
  unfold msm8.pairs.batch_inverse_loop1
  have hs := two_pow_32_le_usize
  repeat' (rw [loop.eq_1]; simp (disch := (first | decide | (simp only [UScalar.ofNatCore_val_eq]; omega))) [
    msm8.pairs.batch_inverse_loop1.body, sub_ok,
    index_usize_eq, update_eq, Fp8.mul_refines])

theorem Msm8.batchInverse_refines (values : Array fp8.Fp8 4#usize) :
    msm8.pairs.batch_inverse values =
      ok (toArray toFp8 (Msm8.batchInverse (ofArray ofFp8 values))) := by
  let v : Vector Fp8 4 := ofArray ofFp8 values (by simp)
  have hv : values = toArray toFp8 v := by simp [v]
  rw [hv]
  simp only [ofArray_toArray ofFp8_toFp8]
  unfold msm8.pairs.batch_inverse
  rw [batchPrefix_refines]
  simp (disch := decide) [msm8.pairs.CHAINS, sub_ok,
    index_usize_eq, Fp8.inverse_refines, Fp8.zero_refines]
  rw [← toArray_replicate toFp8 Fp8.zero (show (4#usize).val = 4 by simp)]
  rw [batchSuffix_refines]
  simp (disch := decide) [update_eq]
  congr 1

end LeanBlsSimd
