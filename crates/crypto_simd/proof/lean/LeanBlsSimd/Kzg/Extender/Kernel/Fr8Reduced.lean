import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Model
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Offset

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.FrModel

def Fr8.reduced (x : Fr8) : Fr8 :=
  let (d, borrow) := Simd.sub_limbs x.limbs Simd.two_p
  ⟨Simd.blend (Simd.borrowed borrow) d x.limbs⟩

theorem Fr8.reduced_refines (a : fr8.Fr8) :
    fr8.Fr8.reduced a = ok (toFr8 (ofFr8 a).reduced) := by
  have htwo : fr8.Fr8.multiple_of_r 2#u64 = ok (toArray id Simd.two_p) := by
    have h := (Kzg.Extender.Kernel.multiple_of_r_nat_refinement 2 (by decide)).1
    exact h.trans (congrArg Result.ok (by rfl))
  simp [fr8.Fr8.reduced, htwo, Simd.sub_limbs_refines, Simd.select_borrowed_refines,
    Fr8.reduced, ofFr8, toFr8, Function.uncurry_def]

theorem Fr8.lane_reduced {x : Fr8} {l : Fin 8}
    (hn : ∀ j : Fin LIMBS, (x.lane l)[j].toNat < 2 ^ 52)
    (hx : val (x.lane l) < 4 * Fr.modulus) :
    Fr8Inv (x.reduced.lane l) ∧
      val (x.reduced.lane l) = val (x.lane l) % (2 * Fr.modulus) ∧
      (val (x.reduced.lane l) : ZMod Fr.modulus) = val (x.lane l) := by
  have hl := Simd.sub_limbs_lane x.limbs Simd.two_p l
  rw [Simd.laneOf_two_p, ← lane_eq] at hl
  obtain ⟨hdn, hb, hv⟩ := Lane.sub_limbs_spec hn normal_two_p
  rw [← hl] at hdn hb hv
  unfold reduced
  generalize Simd.sub_limbs x.limbs Simd.two_p = st at hdn hb hv ⊢
  obtain ⟨d, borrow⟩ := st
  simp only at hdn hb hv
  simp only [lane_mk]
  rw [Simd.laneOf_blend, Simd.testBit_borrowed, hb, Lane.decide_borrowOf, val_two_p]
  rw [val_two_p] at hv
  by_cases hlt : val (x.lane l) < 2 * Fr.modulus
  · simp only [hlt, decide_true, if_true]
    exact ⟨⟨hn, hlt⟩, (Nat.mod_eq_of_lt hlt).symm, rfl⟩
  · simp only [hlt, decide_false, Bool.false_eq_true, if_false, Bool.toNat_false,
      zero_mul, add_zero] at hv ⊢
    have he : val (laneOf d l) = val (x.lane l) - 2 * Fr.modulus := by omega
    refine ⟨⟨hdn, by omega⟩, ?_, ?_⟩
    · rw [he, Nat.mod_eq_sub_mod (by omega), Nat.mod_eq_of_lt (by omega)]
    · rw [he, Nat.cast_sub (by omega)]
      push_cast
      rw [ZMod.natCast_self]
      ring

end LeanBlsSimd.FrModel

namespace LeanBlsSimd.Kzg.Extender.Kernel

open scoped EthLib.Cryptography.Bls.Fr

theorem reduced_refinement (a : fr8.Fr8) (hn : Normalized a)
    (ha : ∀ lane, laneNat a lane < 4 * Fr.modulus) :
    ∃ out, fr8.Fr8.reduced a = ok out ∧ Bounded out ∧
      ∀ lane, laneNat out lane = laneNat a lane % (2 * Fr.modulus) ∧
        laneValue out lane = laneValue a lane := by
  let out := FrModel.toFr8 (FrModel.ofFr8 a).reduced
  have h lane := FrModel.Fr8.lane_reduced ((normalized_iff_model a).mp hn lane)
    (show FrModel.val ((FrModel.ofFr8 a).lane lane) < 4 * Fr.modulus by
      simpa only [laneNat_eq_val] using ha lane)
  refine ⟨out, FrModel.Fr8.reduced_refines a, (bounded_iff_model out).mpr ?_, ?_⟩
  · intro lane
    simpa only [out, FrModel.ofFr8_toFr8] using (h lane).1
  · intro lane
    constructor
    · simpa only [laneNat_eq_val, out, FrModel.ofFr8_toFr8] using (h lane).2.1
    · simpa only [laneValue, laneNat_eq_val, out, FrModel.ofFr8_toFr8,
        Fr.ofNat_eq_natCast] using (h lane).2.2

end LeanBlsSimd.Kzg.Extender.Kernel
