import LeanBlsSimd.Refines.Fr8
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Lazy
import LeanBlsSimd.Proofs.Fr8Product

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg
open scoped EthLib.Cryptography.Bls.Fr

namespace LeanBlsSimd.Kzg.Extender.Kernel

set_option exponentiation.threshold 1000 in
theorem mul_refinement (a b : fr8.Fr8) (ha : Normalized a) (hb : Normalized b)
    (hab : ∀ lane, laneNat a lane * laneNat b lane < Fr.modulus * 2 ^ 260) :
    ∃ out, fr8.Fr8.mul a b = ok out ∧ Lazy 2 32 out ∧
      ∀ lane, lazyLaneValue out lane =
        laneValue a lane * laneValue b lane * (Fr.ofNat (2 ^ 260)).inverse := by
  let out := FrModel.toFr8 ((FrModel.ofFr8 a).mulRaw (FrModel.ofFr8 b))
  have h lane := FrModel.Fr8.mulRaw_spec lane ((normalized_iff_model a).mp ha lane)
    ((normalized_iff_model b).mp hb lane)
    (show FrModel.val ((FrModel.ofFr8 a).lane lane) *
      FrModel.val ((FrModel.ofFr8 b).lane lane) < Fr.modulus * FrModel.R by
        simpa only [laneNat_eq_val, FrModel.R, FrModel.LIMBS, FrModel.LIMB_BITS] using hab lane)
  have hl (lane : Fin 8) (j : Fin 5) : (out.val[j.val]!)[lane].toNat < 2 ^ 57 := by
    rw [← getElem_lane_ofFr8]
    simpa only [out, FrModel.ofFr8_toFr8] using (h lane).1 j
  have he lane : laneInt out lane = (laneNat out lane : ℤ) := by
    unfold laneInt laneNat
    rw [Fin.sum_univ_def]
    push_cast
    simp only [List.map_map]
    apply congrArg List.sum
    apply List.map_congr_left
    intro j _
    rw [SignedLimbs.limb_eq_nat (by have := hl lane j; omega)]
    simp
  refine ⟨out, FrModel.Fr8.mul_refines a b, fun lane => ?_, fun lane => ?_⟩
  · refine ⟨by rw [he]; positivity, ?_, fun j => ?_⟩
    · rw [he, laneNat_eq_val]
      have hv := (h lane).2.1
      simpa only [out, FrModel.ofFr8_toFr8] using (show
        (FrModel.val (((FrModel.ofFr8 a).mulRaw (FrModel.ofFr8 b)).lane lane) : ℤ) <
          2 * Fr.modulus by exact_mod_cast hv)
    · rw [SignedLimbs.limb_eq_nat (by have := hl lane j; omega),
        abs_of_nonneg (by positivity)]
      have := hl lane j
      norm_num at *
      omega
  · rw [lazyLaneValue, he, Int.cast_natCast, Fr.inverse_eq_inv]
    simpa only [laneValue, laneNat_eq_val, out, FrModel.ofFr8_toFr8,
      Fr.ofNat_eq_natCast, FrModel.R, FrModel.LIMBS, FrModel.LIMB_BITS, Nat.reduceMul]
      using (h lane).2.2

private theorem mul_scale_cancel (x y r : Fr) (hr : r ≠ 0) :
    x * (y * r) * r.inverse = x * y := by
  have hri : r * r.inverse = (1 : Fr) := by
    rw [Fr.inverse_eq_inv]
    exact mul_inv_cancel₀ hr
  rw [Fr.mul_assoc, Fr.mul_assoc, hri, Fin.mul_one]

set_option exponentiation.threshold 1000 in
theorem mul_multiplier_refinement (a w : fr8.Fr8) (values factors : Fin 8 → Fr)
    (ha : Normalized a) (hav : ∀ lane, laneValue a lane = values lane)
    (hw : MultiplierRep w factors) :
    ∃ out, fr8.Fr8.mul a w = ok out ∧
      LazyRep 2 32 out (fun lane => values lane * factors lane) := by
  have hab lane : laneNat a lane * laneNat w lane < Fr.modulus * 2 ^ 260 := by
    have ha' : laneNat a lane < 2 ^ 260 := by
      rw [laneNat_eq_val]
      exact FrModel.Lane.val_lt_R ((normalized_iff_model a).mp ha lane)
    have hw' := hw.2 lane
    have hr : 0 < Fr.modulus := by decide +kernel
    calc
      laneNat a lane * laneNat w lane ≤ laneNat a lane * Fr.modulus :=
        Nat.mul_le_mul_left _ hw'.le
      _ < 2 ^ 260 * Fr.modulus := Nat.mul_lt_mul_of_pos_right ha' hr
      _ = Fr.modulus * 2 ^ 260 := Nat.mul_comm _ _
  obtain ⟨out, hout, hb, hm⟩ := mul_refinement a w ha hw.1.1.1 hab
  refine ⟨out, hout, hb, fun lane => ?_⟩
  have hR : Fr.ofNat (2 ^ 260) ≠ 0 := by
    rw [Fr.ofNat_eq_natCast]
    change ((2 ^ 260 : Nat) : ZMod Fr.modulus) ≠ 0
    rw [Ne, ZMod.natCast_eq_zero_iff]
    decide +kernel
  rw [hm lane, hav lane, hw.1.2 lane]
  exact mul_scale_cancel (values lane) (factors lane) _ hR

theorem normalise_mul_multiplier_refinement {k m : Nat}
    (a w : fr8.Fr8) (values factors : Fin 8 → Fr)
    (ha : LazyRep k m a values) (hk : k ≤ 35) (hm : m ≤ 1024)
    (hw : MultiplierRep w factors) :
    ∃ norm out, fr8.Fr8.normalise a = ok norm ∧ fr8.Fr8.mul norm w = ok out ∧
      LazyRep 2 32 out (fun lane => values lane * factors lane) := by
  obtain ⟨norm, hn, hnorm, he⟩ := normalise_lazy_refinement a values ha hk hm
  obtain ⟨out, ho, hrep⟩ :=
    mul_multiplier_refinement norm w values factors hnorm (fun lane => (he lane).2) hw
  exact ⟨norm, out, hn, ho, hrep⟩

end LeanBlsSimd.Kzg.Extender.Kernel
