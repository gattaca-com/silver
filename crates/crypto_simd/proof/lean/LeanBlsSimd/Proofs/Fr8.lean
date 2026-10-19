import LeanBlsSimd.Proofs.Fr8Carries

namespace LeanBlsSimd.FrModel

open EthCryptographySpecs.Bls

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
  · simp only [hlt, decide_true, if_true]
    exact ⟨h, (Nat.mod_eq_of_lt hlt).symm⟩
  · simp only [hlt, decide_false, Bool.false_eq_true, if_false, Bool.toNat_false, zero_mul,
      add_zero] at hv ⊢
    refine ⟨⟨fun j => hdn j, by omega⟩, ?_⟩
    rw [Nat.mod_eq_sub_mod (by omega), Nat.mod_eq_of_lt (by omega)]
    omega

theorem lane_add {x y : Fr8} {l : Fin 8} (hx : Fr8Inv (x.lane l)) (hy : Fr8Inv (y.lane l)) :
    Fr8Inv ((x.add y).lane l) ∧
      val ((x.add y).lane l) = (val (x.lane l) + val (y.lane l)) % (2 * Fr.modulus) ∧
      (val ((x.add y).lane l) : ZMod Fr.modulus) = val (x.lane l) + val (y.lane l) := by
  have hs := Simd.add_limbs_lane x.limbs y.limbs l
  rw [← lane_eq x l, ← lane_eq y l] at hs
  obtain ⟨hsn, hsv⟩ := Lane.add_limbs_spec (fun j => hx.normal j) (fun j => hy.normal j)
  rw [← hs] at hsn hsv
  have hxb := hx.bound
  have hyb := hy.bound
  have hR := four_mul_p_lt_R
  rw [Nat.mod_eq_of_lt (by omega)] at hsv
  have hl := Simd.sub_limbs_lane (Simd.add_limbs x.limbs y.limbs) Simd.two_p l
  rw [Simd.laneOf_two_p] at hl
  obtain ⟨hdn, hb, hv⟩ := Lane.sub_limbs_spec hsn normal_two_p
  rw [← hl] at hdn hb hv
  unfold add
  dsimp only
  generalize Simd.add_limbs x.limbs y.limbs = s at hsn hsv hdn hb hv ⊢
  generalize Simd.sub_limbs s Simd.two_p = st at hdn hb hv ⊢
  obtain ⟨d, borrow⟩ := st
  simp only at hdn hb hv
  simp only [lane_mk]
  rw [Simd.laneOf_blend, Simd.testBit_borrowed, hb, Lane.decide_borrowOf, val_two_p]
  rw [val_two_p] at hv
  by_cases hlt : val (laneOf s l) < 2 * Fr.modulus
  · simp only [hlt, decide_true, if_true]
    exact ⟨⟨hsn, hlt⟩, by rw [← hsv, Nat.mod_eq_of_lt hlt], by rw [hsv]; push_cast; rfl⟩
  · simp only [hlt, decide_false, Bool.false_eq_true, if_false, Bool.toNat_false, zero_mul,
      add_zero] at hv ⊢
    refine ⟨⟨hdn, by omega⟩, ?_⟩
    have : val (laneOf d l) = val (x.lane l) + val (y.lane l) - 2 * Fr.modulus := by omega
    constructor
    · rw [this, Nat.mod_eq_sub_mod (by omega), Nat.mod_eq_of_lt (by omega)]
    · rw [this, Nat.cast_sub (by omega)]
      push_cast
      rw [ZMod.natCast_self]
      ring

theorem lane_sub {x y : Fr8} {l : Fin 8} (hx : Fr8Inv (x.lane l)) (hy : Fr8Inv (y.lane l)) :
    Fr8Inv ((x.sub y).lane l) ∧
      val ((x.sub y).lane l) = (val (x.lane l) + 2 * Fr.modulus - val (y.lane l)) % (2 * Fr.modulus) ∧
      (val ((x.sub y).lane l) : ZMod Fr.modulus) = val (x.lane l) - val (y.lane l) := by
  have hl := Simd.sub_limbs_lane x.limbs y.limbs l
  rw [← lane_eq x l, ← lane_eq y l] at hl
  obtain ⟨hdn, hb, hv⟩ := Lane.sub_limbs_spec (fun j => hx.normal j) (fun j => hy.normal j)
  rw [← hl] at hdn hb hv
  have hw := Simd.add_limbs_lane (Simd.sub_limbs x.limbs y.limbs).1 Simd.two_p l
  rw [Simd.laneOf_two_p] at hw
  obtain ⟨hwn, hwv⟩ := Lane.add_limbs_spec hdn normal_two_p
  rw [← hw, val_two_p] at hwv
  rw [← hw] at hwn
  unfold sub
  dsimp only
  generalize Simd.sub_limbs x.limbs y.limbs = st at hdn hb hv hwn hwv ⊢
  obtain ⟨d, borrow⟩ := st
  simp only at hdn hb hv hwn hwv
  simp only [lane_mk]
  rw [Simd.laneOf_blend, Simd.testBit_borrowed, hb, Lane.decide_borrowOf]
  have hxb := hx.bound
  have hyb := hy.bound
  have hR := four_mul_p_lt_R
  have hdR := Lane.val_lt_R hdn
  by_cases hlt : val (x.lane l) < val (y.lane l)
  · simp only [hlt, decide_true, if_true, Bool.toNat_true, one_mul] at hv ⊢
    have hw' : val (laneOf (Simd.add_limbs d Simd.two_p) l) =
        val (x.lane l) + 2 * Fr.modulus - val (y.lane l) := by
      rw [hwv, show val (laneOf d l) + 2 * Fr.modulus =
        (val (x.lane l) + 2 * Fr.modulus - val (y.lane l)) + R by omega,
        Nat.add_mod_right, Nat.mod_eq_of_lt (by omega)]
    refine ⟨⟨hwn, by omega⟩, ?_⟩
    constructor
    · rw [hw', Nat.mod_eq_of_lt (by omega)]
    · rw [hw', Nat.cast_sub (by omega)]
      push_cast
      rw [ZMod.natCast_self]
      ring
  · simp only [hlt, decide_false, Bool.false_eq_true, if_false, Bool.toNat_false, zero_mul,
      add_zero] at hv ⊢
    refine ⟨⟨hdn, by omega⟩, ?_⟩
    constructor
    · rw [show val (x.lane l) + 2 * Fr.modulus - val (y.lane l) =
        val (laneOf d l) + 2 * Fr.modulus by omega, Nat.add_mod_right,
        Nat.mod_eq_of_lt (by omega)]
    · rw [show val (laneOf d l) = val (x.lane l) - val (y.lane l) by omega,
        Nat.cast_sub (by omega)]


end Fr8

end LeanBlsSimd.FrModel
