import LeanBlsSimd.Proofs.Carries

/-!
# The `Fp8` operations, lane by lane

Each theorem speaks of one lane `l` and assumes `Fp8Inv` of that lane only, so it holds whatever
the other lanes hold. `decode` reads a lane as the field element it holds in Montgomery form,
value · R⁻¹ with R = 2^416. In that form the operations are the field's, with no R:
`decode_lane_mul`, `decode_lane_add`, `decode_lane_sub`, `decode_lane_neg`, `lane_half`
and `decode_lane_canonical`. Each `lane_*` theorem also keeps `Fp8Inv`.

`sub` relies on `add_limbs` dropping its top carry: where the subtraction borrowed, its limbs
hold val x − val y + R, and adding 2p wraps them to val x − val y + 2p, below 2p.

`canonical` maps a value below 2p to its residue below p (`lane_canonical`). Bit `l` of
`eq_mask` is set exactly when the two lanes hold the same field element (`testBit_eq_mask`), and
bit `l` of `is_zero_mask` exactly when lane `l` holds zero (`testBit_is_zero_mask`).
-/

namespace LeanBlsSimd

open EthCryptographySpecs.Bls

/-- The field element a lane holds in Montgomery form, with R = 2^416. -/
def decode (a : Limbs) : ZMod Fp.modulus := (val a : ZMod Fp.modulus) * (R : ZMod Fp.modulus)⁻¹

set_option exponentiation.threshold 1000 in
theorem R_ne_zero : (R : ZMod Fp.modulus) ≠ 0 := by
  rw [Ne, ZMod.natCast_eq_zero_iff]
  decide

theorem decode_eq_iff {a b : Limbs} : decode a = decode b ↔ (val a : ZMod Fp.modulus) = val b :=
  mul_left_inj' (inv_ne_zero R_ne_zero)

theorem decode_eq_zero_iff {a : Limbs} : decode a = 0 ↔ (val a : ZMod Fp.modulus) = 0 := by
  simp [decode, R_ne_zero]

theorem decode_of_val {a : Limbs} {n : ℕ} (h : val a = n * R % Fp.modulus) :
    decode a = n := by
  rw [decode, h, ZMod.natCast_mod, Nat.cast_mul, mul_assoc, mul_inv_cancel₀ R_ne_zero, mul_one]

theorem normal_ofList_P : ∀ j : Fin LIMBS, (Limbs.ofList P)[j].toNat < 2 ^ 52 := by decide

theorem val_ofList_P : val (Limbs.ofList P) = Fp.modulus := by decide +kernel

set_option exponentiation.threshold 1000 in
theorem normal_two_p : ∀ j : Fin LIMBS,
    (Limbs.ofList (limbs52 (2 * Fp.modulus)))[j].toNat < 2 ^ 52 := by
  decide +kernel

theorem val_two_p : val (Limbs.ofList (limbs52 (2 * Fp.modulus))) = 2 * Fp.modulus := by
  decide +kernel

theorem Simd.laneOf_two_p (l : Fin 8) :
    laneOf Simd.two_p l = Limbs.ofList (limbs52 (2 * Fp.modulus)) := by
  rw [Simd.two_p, Simd.add_limbs_lane, Simd.laneOf_splat_limbs]
  decide +kernel

theorem inv_ofList_R_MOD_P : Fp8Inv (.ofList R_MOD_P) := ⟨by decide, by decide +kernel⟩

theorem decode_ofList_R_MOD_P : decode (.ofList R_MOD_P) = 1 := by
  have h : val (.ofList R_MOD_P) = 1 * R % Fp.modulus := by decide +kernel
  rw [decode_of_val h, Nat.cast_one]

theorem inv_ofList_R2_MOD_P : Fp8Inv (.ofList R2_MOD_P) := ⟨by decide, by decide +kernel⟩

theorem decode_ofList_R2_MOD_P : decode (.ofList R2_MOD_P) = R := by
  have h : val (.ofList R2_MOD_P) = R * R % Fp.modulus := by decide +kernel
  rw [decode_of_val h]

theorem inv_ofList_ONE_PLAIN : Fp8Inv (.ofList ONE_PLAIN) := ⟨by decide, by decide +kernel⟩

theorem val_ofList_ONE_PLAIN : val (.ofList ONE_PLAIN) = 1 := by decide +kernel

theorem inv_ofList_TWO_POW_384_MOD_P : Fp8Inv (.ofList TWO_POW_384_MOD_P) :=
  ⟨by decide, by decide +kernel⟩

set_option exponentiation.threshold 1000 in
theorem val_ofList_TWO_POW_384_MOD_P :
    val (.ofList TWO_POW_384_MOD_P) = 2 ^ 384 % Fp.modulus := by
  decide +kernel

theorem inv_ofList_HALF_MONT : Fp8Inv (.ofList HALF_MONT) := ⟨by decide, by decide +kernel⟩

theorem decode_ofList_HALF_MONT : decode (.ofList HALF_MONT) = 2⁻¹ := by
  have h : val (.ofList HALF_MONT) = half * R % Fp.modulus := by decide +kernel
  rw [decode_of_val h]
  have h2 := congrArg (Nat.cast : ℕ → ZMod Fp.modulus) half_spec
  rw [ZMod.natCast_mod, Nat.cast_mul, Nat.cast_one, Nat.cast_ofNat] at h2
  exact eq_inv_of_mul_eq_one_right h2

theorem normal_ofList_HALF_P_MINUS_1 : ∀ j : Fin LIMBS, (Limbs.ofList HALF_P_MINUS_1)[j].toNat < 2 ^ 52 := by
  decide

theorem val_ofList_HALF_P_MINUS_1 : val (.ofList HALF_P_MINUS_1) = (Fp.modulus - 1) / 2 := by
  decide +kernel

theorem decode_mul {a b : Limbs} (ha : Fp8Inv a) (hb : Fp8Inv b) :
    decode (Lane.mul a b) = decode a * decode b := by
  rw [decode, (mul_spec ha hb).2, decode, decode]
  ring

namespace Fp8

theorem lane_mk (v : Vector M512 LIMBS) (l : Fin 8) : (⟨v⟩ : Fp8).lane l = laneOf v l := rfl

theorem lane_splat_limbs (t : Limbs) (l : Fin 8) : (splat_limbs t).lane l = t :=
  Simd.laneOf_splat_limbs t l

theorem lane_zero (l : Fin 8) : zero.lane l = .replicate _ 0 := by
  ext j hj
  simp [lane, zero]

theorem inv_zero (l : Fin 8) : Fp8Inv (zero.lane l) := by
  rw [lane_zero]
  exact ⟨by decide, by decide +kernel⟩

theorem lane_one (l : Fin 8) : one.lane l = .ofList R_MOD_P := lane_splat_limbs _ l

theorem inv_one (l : Fin 8) : Fp8Inv (one.lane l) := by
  rw [lane_one]
  exact inv_ofList_R_MOD_P

theorem decode_lane_one (l : Fin 8) : decode (one.lane l) = 1 := by
  rw [lane_one, decode_ofList_R_MOD_P]

theorem decode_lane_zero (l : Fin 8) : decode (zero.lane l) = 0 := by
  rw [lane_zero, decode, val_replicate_zero]
  simp

theorem lane_mul (x y : Fp8) (l : Fin 8) : (x.mul y).lane l = Lane.mul (x.lane l) (y.lane l) := by
  rw [mul, lane_ofLanes]
  simp

theorem inv_mul {x y : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) (hy : Fp8Inv (y.lane l)) :
    Fp8Inv ((x.mul y).lane l) := by
  rw [lane_mul]
  exact (LeanBlsSimd.mul_spec hx hy).1

theorem decode_lane_mul {x y : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) (hy : Fp8Inv (y.lane l)) :
    decode ((x.mul y).lane l) = decode (x.lane l) * decode (y.lane l) := by
  rw [lane_mul, decode_mul hx hy]

theorem decode_lane_square {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) :
    decode (x.square.lane l) = decode (x.lane l) ^ 2 := by
  rw [square, decode_lane_mul hx hx, sq]

theorem lane_select (k : Mmask8) (a b : Fp8) (l : Fin 8) :
    (select k a b).lane l = if k.toNat.testBit l then b.lane l else a.lane l :=
  Simd.laneOf_blend k a.limbs b.limbs l

theorem lane_canonical {x : Fp8} {l : Fin 8} (h : Fp8Inv (x.lane l)) :
    Fp8Inv (x.canonical.lane l) ∧ val (x.canonical.lane l) = val (x.lane l) % Fp.modulus := by
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
  by_cases hlt : val (x.lane l) < Fp.modulus
  · simp only [hlt, decide_true, if_true]
    exact ⟨h, (Nat.mod_eq_of_lt hlt).symm⟩
  · simp only [hlt, decide_false, Bool.false_eq_true, if_false, Bool.toNat_false, zero_mul,
      add_zero] at hv ⊢
    refine ⟨⟨fun j => hdn j, by omega⟩, ?_⟩
    rw [Nat.mod_eq_sub_mod (by omega), Nat.mod_eq_of_lt (by omega)]
    omega

theorem decode_lane_canonical {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) :
    decode (x.canonical.lane l) = decode (x.lane l) := by
  rw [decode_eq_iff, (lane_canonical hx).2, ZMod.natCast_mod]

theorem testBit_eq_mask {x y : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) (hy : Fp8Inv (y.lane l)) :
    (x.eq_mask y).toNat.testBit l = decide (decode (x.lane l) = decode (y.lane l)) := by
  obtain ⟨ha, hav⟩ := lane_canonical hx
  obtain ⟨hb, hbv⟩ := lane_canonical hy
  rw [eq_mask, testBit_foldl_cmpeq, decide_eq_decide, decode_eq_iff,
    ZMod.natCast_eq_natCast_iff', ← hav, ← hbv]
  constructor
  · intro h
    have : x.canonical.lane l = y.canonical.lane l :=
      Vector.ext fun j hj => by simpa [lane] using h ⟨j, hj⟩
    rw [this]
  · intro h j
    have := congrArg (·[j]) (eq_of_val_eq (fun j => ha.normal j) (fun j => hb.normal j) h)
    simpa [lane] using this

theorem testBit_is_zero_mask {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) :
    x.is_zero_mask.toNat.testBit l = decide (decode (x.lane l) = 0) := by
  obtain ⟨ha, hav⟩ := lane_canonical hx
  rw [is_zero_mask, testBit_foldl_cmpeq, decide_eq_decide, decode_eq_zero_iff,
    ZMod.natCast_eq_zero_iff, Nat.dvd_iff_mod_eq_zero, ← hav, val_eq_zero_iff]
  constructor
  · intro h
    exact Vector.ext fun j hj => by simpa [lane] using h ⟨j, hj⟩
  · intro h j
    have := congrArg (·[j]) h
    simpa [lane] using this

theorem lane_add {x y : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) (hy : Fp8Inv (y.lane l)) :
    Fp8Inv ((x.add y).lane l) ∧
      (val ((x.add y).lane l) : ZMod Fp.modulus) = val (x.lane l) + val (y.lane l) := by
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
  by_cases hlt : val (laneOf s l) < 2 * Fp.modulus
  · simp only [hlt, decide_true, if_true]
    exact ⟨⟨hsn, hlt⟩, by rw [hsv]; push_cast; rfl⟩
  · simp only [hlt, decide_false, Bool.false_eq_true, if_false, Bool.toNat_false, zero_mul,
      add_zero] at hv ⊢
    refine ⟨⟨hdn, by omega⟩, ?_⟩
    have : val (laneOf d l) = val (x.lane l) + val (y.lane l) - 2 * Fp.modulus := by omega
    rw [this, Nat.cast_sub (by omega)]
    push_cast
    rw [ZMod.natCast_self]
    ring

theorem decode_lane_add {x y : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) (hy : Fp8Inv (y.lane l)) :
    decode ((x.add y).lane l) = decode (x.lane l) + decode (y.lane l) := by
  rw [decode, (lane_add hx hy).2, decode, decode]
  ring

theorem decode_lane_double {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) :
    decode (x.double.lane l) = 2 * decode (x.lane l) := by
  rw [double, decode_lane_add hx hx]
  ring

theorem lane_sub {x y : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) (hy : Fp8Inv (y.lane l)) :
    Fp8Inv ((x.sub y).lane l) ∧
      (val ((x.sub y).lane l) : ZMod Fp.modulus) = val (x.lane l) - val (y.lane l) := by
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
        val (x.lane l) + 2 * Fp.modulus - val (y.lane l) := by
      rw [hwv, show val (laneOf d l) + 2 * Fp.modulus =
        (val (x.lane l) + 2 * Fp.modulus - val (y.lane l)) + R by omega,
        Nat.add_mod_right, Nat.mod_eq_of_lt (by omega)]
    refine ⟨⟨hwn, by omega⟩, ?_⟩
    rw [hw', Nat.cast_sub (by omega)]
    push_cast
    rw [ZMod.natCast_self]
    ring
  · simp only [hlt, decide_false, Bool.false_eq_true, if_false, Bool.toNat_false, zero_mul,
      add_zero] at hv ⊢
    refine ⟨⟨hdn, by omega⟩, ?_⟩
    rw [show val (laneOf d l) = val (x.lane l) - val (y.lane l) by omega, Nat.cast_sub (by omega)]

theorem decode_lane_sub {x y : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) (hy : Fp8Inv (y.lane l)) :
    decode ((x.sub y).lane l) = decode (x.lane l) - decode (y.lane l) := by
  rw [decode, (lane_sub hx hy).2, decode, decode]
  ring

theorem lane_neg {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) :
    Fp8Inv (x.neg.lane l) ∧ (val (x.neg.lane l) : ZMod Fp.modulus) = -val (x.lane l) := by
  obtain ⟨h, hv⟩ := lane_sub (inv_zero l) hx
  refine ⟨h, ?_⟩
  rw [neg, hv, lane_zero, val_replicate_zero]
  simp

theorem decode_lane_neg {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) :
    decode (x.neg.lane l) = -decode (x.lane l) := by
  rw [decode, (lane_neg hx).2, decode]
  ring

theorem lane_half {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) :
    Fp8Inv (x.half.lane l) ∧ decode (x.half.lane l) = decode (x.lane l) * 2⁻¹ := by
  have hh : Fp8Inv ((splat_limbs (.ofList HALF_MONT)).lane l) := by
    rw [lane_splat_limbs]
    exact inv_ofList_HALF_MONT
  refine ⟨inv_mul hx hh, ?_⟩
  rw [half, decode_lane_mul hx hh, lane_splat_limbs, decode_ofList_HALF_MONT]

end Fp8

end LeanBlsSimd
