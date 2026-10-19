import LeanBlsSimd.Kzg.Extender.Kernel.Basic
import LeanBlsSimd.Refines.Fr8
import LeanBlsSimd.Proofs.Fr8

open Aeneas Aeneas.Std Result
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel

open scoped EthCryptographySpecs.Bls.Fr

theorem getElem_lane_ofFr8 (x : fr8.Fr8) (j : Fin 5) (lane : Fin 8) :
    ((FrModel.ofFr8 x).lane lane)[j.val] = (x.val[j.val]!)[lane] := by
  have hj : j.val < x.val.length := by rw [x.property]; exact j.isLt
  rw [getElem!_pos x.val j.val hj]
  simp only [FrModel.Fr8.lane, FrModel.ofFr8, Vector.getElem_map, getElem_ofArray, id_eq]

theorem laneNat_eq_val (x : fr8.Fr8) (lane : Fin 8) :
    laneNat x lane = FrModel.val ((FrModel.ofFr8 x).lane lane) := by
  unfold laneNat FrModel.val
  rw [Fin.sum_univ_def]
  apply congrArg List.sum
  apply List.map_congr_left
  intro j _
  change (x.val[j.val]!)[lane].toNat * 2 ^ (52 * j.val) =
    ((FrModel.ofFr8 x).lane lane)[j.val].toNat * 2 ^ (52 * j.val)
  rw [getElem_lane_ofFr8]

theorem normalized_iff_model (x : fr8.Fr8) :
    Normalized x ↔ ∀ lane : Fin 8, ∀ j : Fin FrModel.LIMBS,
      ((FrModel.ofFr8 x).lane lane)[j].toNat < 2 ^ 52 := by
  constructor
  · intro h lane j
    change ((FrModel.ofFr8 x).lane lane)[j.val].toNat < 2 ^ 52
    rw [getElem_lane_ofFr8]
    exact h j lane
  · intro h j lane
    have h' := h lane j
    change ((FrModel.ofFr8 x).lane lane)[j.val].toNat < 2 ^ 52 at h'
    rwa [getElem_lane_ofFr8] at h'

theorem bounded_iff_model (x : fr8.Fr8) :
    Bounded x ↔ ∀ lane : Fin 8, FrModel.Fr8Inv ((FrModel.ofFr8 x).lane lane) := by
  rw [Bounded, normalized_iff_model]
  constructor
  · rintro ⟨hn, hb⟩ lane
    exact ⟨hn lane, by simpa only [laneNat_eq_val] using hb lane⟩
  · intro h
    exact ⟨fun lane => (h lane).normal, fun lane => by
      simpa only [laneNat_eq_val] using (h lane).bound⟩

theorem add_refinement (a b : fr8.Fr8) (ha : Bounded a) (hb : Bounded b) :
    ∃ out, fr8.Fr8.add a b = ok out ∧ Bounded out ∧
      ∀ lane, laneNat out lane = (laneNat a lane + laneNat b lane) % (2 * Fr.modulus) ∧
        laneValue out lane = laneValue a lane + laneValue b lane := by
  let out := FrModel.toFr8 ((FrModel.ofFr8 a).add (FrModel.ofFr8 b))
  have h lane := FrModel.Fr8.lane_add ((bounded_iff_model a).mp ha lane)
    ((bounded_iff_model b).mp hb lane)
  refine ⟨out, FrModel.Fr8.add_refines a b, (bounded_iff_model out).mpr ?_, ?_⟩
  · intro lane
    simpa only [out, FrModel.ofFr8_toFr8] using (h lane).1
  · intro lane
    constructor
    · simpa only [laneNat_eq_val, out, FrModel.ofFr8_toFr8] using (h lane).2.1
    · simpa only [laneValue, laneNat_eq_val, out, FrModel.ofFr8_toFr8,
        Fr.ofNat_eq_natCast] using (h lane).2.2

theorem sub_refinement (a b : fr8.Fr8) (ha : Bounded a) (hb : Bounded b) :
    ∃ out, fr8.Fr8.sub a b = ok out ∧ Bounded out ∧
      ∀ lane, laneNat out lane =
          (laneNat a lane + 2 * Fr.modulus - laneNat b lane) % (2 * Fr.modulus) ∧
        laneValue out lane = laneValue a lane - laneValue b lane := by
  let out := FrModel.toFr8 ((FrModel.ofFr8 a).sub (FrModel.ofFr8 b))
  have h lane := FrModel.Fr8.lane_sub ((bounded_iff_model a).mp ha lane)
    ((bounded_iff_model b).mp hb lane)
  refine ⟨out, FrModel.Fr8.sub_refines a b, (bounded_iff_model out).mpr ?_, ?_⟩
  · intro lane
    simpa only [out, FrModel.ofFr8_toFr8] using (h lane).1
  · intro lane
    constructor
    · simpa only [laneNat_eq_val, out, FrModel.ofFr8_toFr8] using (h lane).2.1
    · simpa only [laneValue, laneNat_eq_val, out, FrModel.ofFr8_toFr8,
        Fr.ofNat_eq_natCast] using (h lane).2.2

theorem mul_refinement (a b : fr8.Fr8) (ha : Bounded a) (hb : Bounded b) :
    ∃ out, fr8.Fr8.mul a b = ok out ∧ Bounded out ∧
      ∀ lane, laneValue out lane =
        laneValue a lane * laneValue b lane * (Fr.ofNat (2 ^ 260)).inverse := by
  let out := FrModel.toFr8 ((FrModel.ofFr8 a).mul (FrModel.ofFr8 b))
  have h lane := FrModel.Fr8.mul_spec ((bounded_iff_model a).mp ha)
    ((bounded_iff_model b).mp hb) lane
  refine ⟨out, FrModel.Fr8.mul_refines a b, (bounded_iff_model out).mpr ?_, ?_⟩
  · intro lane
    simpa only [out, FrModel.ofFr8_toFr8] using (h lane).1
  · intro lane
    rw [Fr.inverse_eq_inv]
    simpa only [laneValue, laneNat_eq_val, out, FrModel.ofFr8_toFr8,
      Fr.ofNat_eq_natCast, FrModel.R, FrModel.LIMBS, FrModel.LIMB_BITS, Nat.reduceMul]
      using (h lane).2

private theorem mul_scale_cancel (x y r : Fr) (hr : r ≠ 0) :
    x * (y * r) * r.inverse = x * y := by
  have hri : r * r.inverse = (1 : Fr) := by
    rw [Fr.inverse_eq_inv]
    exact mul_inv_cancel₀ hr
  rw [Fr.mul_assoc, Fr.mul_assoc, hri, Fin.mul_one]

theorem mul_multiplier_refinement (a w : fr8.Fr8) (values factors : Fin 8 → Fr)
    (ha : Represents a values) (hw : MultiplierRep w factors) :
    ∃ out, fr8.Fr8.mul a w = ok out ∧
      Represents out (fun lane => values lane * factors lane) := by
  obtain ⟨out, hout, hb, hm⟩ := mul_refinement a w ha.1 hw.1
  refine ⟨out, hout, hb, fun lane => ?_⟩
  have hR : Fr.ofNat (2 ^ 260) ≠ 0 := by
    rw [Fr.ofNat_eq_natCast]
    change ((2 ^ 260 : Nat) : ZMod Fr.modulus) ≠ 0
    rw [Ne, ZMod.natCast_eq_zero_iff]
    decide +kernel
  rw [hm lane, ha.2 lane, hw.2 lane]
  exact mul_scale_cancel (values lane) (factors lane) _ hR

theorem canonical_refinement (a : fr8.Fr8) (ha : Bounded a) :
    ∃ out, fr8.Fr8.canonical a = ok out ∧ Normalized out ∧
      ∀ lane, laneNat out lane = laneNat a lane % Fr.modulus := by
  let out := FrModel.toFr8 (FrModel.ofFr8 a).canonical
  have h lane := FrModel.Fr8.lane_canonical ((bounded_iff_model a).mp ha lane)
  refine ⟨out, FrModel.Fr8.canonical_refines a, (normalized_iff_model out).mpr ?_, ?_⟩
  · intro lane
    simpa only [out, FrModel.ofFr8_toFr8] using (h lane).1.normal
  · intro lane
    simpa only [laneNat_eq_val, out, FrModel.ofFr8_toFr8] using (h lane).2

end LeanBlsSimd.Kzg.Extender.Kernel
