import LeanBlsSimd.Proofs.Fr8Carries

namespace LeanBlsSimd.FrModel

open EthLib.Cryptography.Bls

theorem four_mul_p_lt_R : 4 * Fr.modulus < R := by decide +kernel

theorem normal_ofList_P : ∀ j : Fin LIMBS, (Limbs.ofList P)[j].toNat < 2 ^ 52 := by decide

theorem val_ofList_P : val (Limbs.ofList P) = Fr.modulus := by decide +kernel

def two_p_limbs : Limbs := (Lane.add_limbs (.ofList P) (.ofList P)).1

theorem normal_two_p : ∀ j : Fin LIMBS, two_p_limbs[j].toNat < 2 ^ 52 :=
  (Lane.add_limbs_spec normal_ofList_P normal_ofList_P).1

theorem val_two_p : val two_p_limbs = 2 * Fr.modulus := by
  have h := (Lane.add_limbs_spec normal_ofList_P normal_ofList_P).2
  rw [val_ofList_P, show Fr.modulus + Fr.modulus = 2 * Fr.modulus by omega,
    Nat.mod_eq_of_lt (by have := four_mul_p_lt_R; omega)] at h
  exact h

theorem Simd.laneOf_two_p (l : Fin 8) : laneOf Simd.two_p l = two_p_limbs := by
  simp only [Simd.two_p, Simd.add_limbs_lane, Simd.laneOf_splat_limbs, two_p_limbs]

namespace Fr8

theorem lane_eq (x : Fr8) (l : Fin 8) : x.lane l = laneOf x.limbs l := rfl

theorem lane_mk (v : Vector M512 LIMBS) (l : Fin 8) : (⟨v⟩ : Fr8).lane l = laneOf v l := rfl

theorem lane_canonical {x : Fr8} {l : Fin 8} (h : Fr8Inv (x.lane l)) :
    Fr8Inv (x.canonical.lane l) ∧ val (x.canonical.lane l) = val (x.lane l) % Fr.modulus := by
  have hl := Simd.sub_limbs_lane x.limbs (Simd.splat_limbs (.ofList P)) l
  rw [Simd.laneOf_splat_limbs, ← lane_eq] at hl
  obtain ⟨hdn, hb, hv⟩ := Lane.sub_limbs_spec (fun j => h.normal j) normal_ofList_P
  rw [← hl] at hdn hb hv
  unfold canonical
  generalize Simd.sub_limbs x.limbs (Simd.splat_limbs (.ofList P)) = st at hdn hb hv ⊢
  obtain ⟨d, borrow⟩ := st
  simp only at hdn hb hv
  simp only [lane_mk]
  rw [Simd.laneOf_blend, Simd.testBit_borrowed, hb, Lane.decide_borrowOf, val_ofList_P]
  rw [val_ofList_P] at hv
  have hx := h.bound
  by_cases hlt : val (x.lane l) < Fr.modulus
  · simp only [hlt, decide_true, ite_true]
    exact ⟨h, (Nat.mod_eq_of_lt hlt).symm⟩
  · simp only [hlt, decide_false, Bool.false_eq_true, ite_false, Bool.toNat_false, zero_mul,
      add_zero] at hv ⊢
    refine ⟨⟨fun j => hdn j, by omega⟩, ?_⟩
    rw [Nat.mod_eq_sub_mod (by omega), Nat.mod_eq_of_lt (by omega)]
    omega


end Fr8

end LeanBlsSimd.FrModel
