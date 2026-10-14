import LeanBlsSimd.Spec.G1

namespace LeanBlsSimd

open EthCryptographySpecs.Bls

theorem BETA_MONT_eq : val (.ofList BETA_MONT) = beta * R % Fp.modulus := by
  decide +kernel

namespace G1x8

structure Holds (self : G1x8) (l : Fin 8) (P : G1) : Prop where
  x : self.x.Holds l P.x
  y : self.y.Holds l P.y
  z : self.z.Holds l P.z

theorem double_correct (self : G1x8) (l : Fin 8) (P : G1)
    (h : self.Holds l P) (hP : G1.Valid P)
    (hu : self.double.2.toNat.testBit l = false) :
    self.double.1.Holds l (G1.double P) := by
  have ha := (Holds.x h).square
  have hb := (Holds.y h).square
  have hc := hb.square
  have hd := ((((Holds.x h).add hb).square.sub ha).sub hc).double
  have he := ha.double.add ha
  have hx3 := he.square.sub hd.double
  have hy3 := (he.mul (hd.sub hx3)).sub hc.double.double.double
  have hz3 := ((Holds.y h).mul (Holds.z h)).double
  have hu' := hu
  simp only [double, Mmask8.testBit_or, Bool.or_eq_false_iff,
    (Holds.y h).testBit_is_zero_mask, (Holds.z h).testBit_is_zero_mask, decide_eq_false_iff_not] at hu'
  have hz : ¬P.z.isZero = true := by
    rw [G1.isZero_iff]
    exact hu'.2
  let x : ZMod Fp.modulus := P.x
  let y : ZMod Fp.modulus := P.y
  let z : ZMod Fp.modulus := P.z
  refine ⟨hx3.of_eq ?_, hy3.of_eq ?_, hz3.of_eq ?_⟩
  all_goals
    simp only [G1.double, if_neg hz]
  · change _ = (3 * (x * x)) * (3 * (x * x)) -
      2 * (2 * ((x + y*y)*(x+y*y) - x*x - (y*y)*(y*y)))
    ring
  · change _ = (3 * (x*x)) *
      (2 * ((x+y*y)*(x+y*y)-x*x-(y*y)*(y*y)) -
        ((3*(x*x))*(3*(x*x))-2*(2*((x+y*y)*(x+y*y)-x*x-(y*y)*(y*y))))) -
      8*((y*y)*(y*y))
    ring
  · change _ = 2 * y * z
    ring

theorem add_affine_correct (self : G1x8) (qx qy : Fp8) (l : Fin 8) (P : G1) (x y : Fp)
    (h : self.Holds l P) (hx : qx.Holds l x) (hy : qy.Holds l y)
    (hP : G1.Valid P) (hQ : G1.Valid ⟨x, y, Fp.one⟩)
    (hu : (self.add_affine qx qy).2.toNat.testBit l = false) :
    (self.add_affine qx qy).1.Holds l (G1.add P ⟨x, y, Fp.one⟩) := by
  have hz1z1 := (Holds.z h).square
  have hs2 := (hy.mul (Holds.z h)).mul hz1z1
  have hh := (hx.mul hz1z1).sub (Holds.x h)
  have hhh := hh.square
  have hi := hhh.double.double
  have hj := hh.mul hi
  have hr := (hs2.sub (Holds.y h)).double
  have hv := (Holds.x h).mul hi
  have hx3 := (hr.square.sub hj).sub hv.double
  have hy3 := (hr.mul (hv.sub hx3)).sub ((Holds.y h).mul hj).double
  have hz3 := (((Holds.z h).add hh).square.sub hz1z1).sub hhh
  have hu' := hu
  simp only [add_affine, Mmask8.testBit_or, hh.testBit_is_zero_mask,
    (Holds.z h).testBit_is_zero_mask, Bool.or_eq_false_iff, decide_eq_false_iff_not] at hu'
  have hz : ¬P.z.isZero = true := G1.isZero_iff.not.mpr hu'.2
  have heq : ¬(P.x * (Fp.one * Fp.one)).beq (x * (P.z * P.z)) = true := by
    rw [G1.beq_iff]
    change ¬(P.x : ZMod Fp.modulus) * (1 * 1) = (x : ZMod Fp.modulus) * (P.z * P.z)
    simpa [sq, sub_eq_zero, eq_comm] using hu'.1
  let X : ZMod Fp.modulus := P.x
  let Y : ZMod Fp.modulus := P.y
  let Z : ZMod Fp.modulus := P.z
  let qX : ZMod Fp.modulus := x
  let qY : ZMod Fp.modulus := y
  let H := qX * (Z * Z) - X * (1 * 1)
  let I := (2 * H) * (2 * H)
  let J := H * I
  let r := 2 * (qY * Z * (Z * Z) - Y * 1 * (1 * 1))
  let V := (X * (1 * 1)) * I
  let outX := r * r - J - 2 * V
  refine ⟨hx3.of_eq ?_, hy3.of_eq ?_, hz3.of_eq ?_⟩
  all_goals simp only [G1.add, if_neg hz, show ¬Fp.one.isZero = true from by decide, heq]
  · change _ = outX
    dsimp [outX, r, J, H, V, I]
    ring
  · change _ = r * (V - outX) - 2 * (Y * 1 * (1 * 1)) * J
    dsimp [outX, r, J, H, V, I]
    ring
  · change _ = ((Z + 1) * (Z + 1) - Z * Z - 1 * 1) * H
    dsimp [H]
    ring

theorem add_correct (self q : G1x8) (l : Fin 8) (P Q : G1)
    (h : self.Holds l P) (hq : q.Holds l Q) (hP : G1.Valid P) (hQ : G1.Valid Q)
    (hu : (self.add q).2.toNat.testBit l = false) :
    (self.add q).1.Holds l (G1.add P Q) := by
  have hz1z1 := (Holds.z h).square
  have hz2z2 := (Holds.z hq).square
  have hu1 := (Holds.x h).mul hz2z2
  have hu2 := (Holds.x hq).mul hz1z1
  have hs1 := ((Holds.y h).mul (Holds.z hq)).mul hz2z2
  have hs2 := ((Holds.y hq).mul (Holds.z h)).mul hz1z1
  have hh := hu2.sub hu1
  have hi := hh.double.square
  have hj := hh.mul hi
  have hr := (hs2.sub hs1).double
  have hv := hu1.mul hi
  have hx3 := (hr.square.sub hj).sub hv.double
  have hy3 := (hr.mul (hv.sub hx3)).sub (hs1.mul hj).double
  have hz3 := ((((Holds.z h).add (Holds.z hq)).square.sub hz1z1).sub hz2z2).mul hh
  have hu' := hu
  simp only [add, Mmask8.testBit_or, hh.testBit_is_zero_mask,
    (Holds.z h).testBit_is_zero_mask, (Holds.z hq).testBit_is_zero_mask,
    Bool.or_eq_false_iff, decide_eq_false_iff_not] at hu'
  have hz : ¬P.z.isZero = true := G1.isZero_iff.not.mpr hu'.1.2
  have hqz : ¬Q.z.isZero = true := G1.isZero_iff.not.mpr hu'.2
  have heq : ¬(P.x * (Q.z * Q.z)).beq (Q.x * (P.z * P.z)) = true := by
    rw [G1.beq_iff]
    simpa only [sq, sub_ne_zero, ne_eq, eq_comm] using hu'.1.1
  let X : ZMod Fp.modulus := P.x
  let Y : ZMod Fp.modulus := P.y
  let Z : ZMod Fp.modulus := P.z
  let qX : ZMod Fp.modulus := Q.x
  let qY : ZMod Fp.modulus := Q.y
  let qZ : ZMod Fp.modulus := Q.z
  let H := qX * (Z * Z) - X * (qZ * qZ)
  let I := (2 * H) * (2 * H)
  let J := H * I
  let r := 2 * (qY * Z * (Z * Z) - Y * qZ * (qZ * qZ))
  let V := (X * (qZ * qZ)) * I
  let outX := r * r - J - 2 * V
  refine ⟨hx3.of_eq ?_, hy3.of_eq ?_, hz3.of_eq ?_⟩
  all_goals simp only [G1.add, if_neg hz, if_neg hqz, if_neg heq]
  · change _ = outX
    dsimp [outX, r, J, H, V, I]
    ring
  · change _ = r * (V - outX) - 2 * (Y * qZ * (qZ * qZ)) * J
    dsimp [outX, r, J, H, V, I]
    ring
  · change _ = ((Z + qZ) * (Z + qZ) - Z * Z - qZ * qZ) * H
    dsimp [H]
    ring

private def scalarStep (n bit : ℕ) : ℕ :=
  if is_lower_z_bit bit then 2 * n + 1 else 2 * n

private theorem scalarChain_eq : (List.range Z_BITS[0]!).reverse.foldl scalarStep 1 = blsX := by
  decide +kernel

theorem times_z_affine_correct (px py : Fp8) (l : Fin 8) (x y : Fp)
    (hx : px.Holds l x) (hy : py.Holds l y) (hP : G1.Valid ⟨x, y, Fp.one⟩)
    (hu : (times_z_affine px py).2.toNat.testBit l = false) :
    ∃ Q, (times_z_affine px py).1.Holds l Q ∧ G1.Valid Q ∧
      G1.toPoint Q = blsX • G1.toPoint ⟨x, y, Fp.one⟩ := by
  let base := G1.toPoint ⟨x, y, Fp.one⟩
  have hfold := List.foldl_rel
    (fun (s : G1x8 × Mmask8) (n : ℕ) => s.2.toNat.testBit l = false →
      ∃ Q, s.1.Holds l Q ∧ G1.Valid Q ∧ G1.toPoint Q = n • base)
    (affineChainStep px py) scalarStep ?_ (List.range Z_BITS[0]!).reverse
    (from_affine px py, 0) 1 ?_
  · simpa only [times_z_affine, scalarChain_eq] using hfold hu
  · rintro ⟨r, u⟩ n bit hrel hclear
    by_cases hb : is_lower_z_bit bit = true
    · simp only [affineChainStep, hb, ↓reduceIte, Mmask8.testBit_or,
        Bool.or_eq_false_iff] at hclear
      obtain ⟨P, hr, hP', hp⟩ := hrel hclear.1.1
      have hd := double_correct r l P hr hP' hclear.1.2
      have hD := G1.valid_double hP'
      refine ⟨G1.add (G1.double P) ⟨x, y, Fp.one⟩, ?_, G1.valid_add hD hP, ?_⟩
      · simpa only [affineChainStep, hb, Bool.false_eq_true, ↓reduceIte] using
          add_affine_correct r.double.1 px py l (G1.double P) x y hd hx hy hD hP hclear.2
      · rw [G1.toPoint_add hD hP, G1.toPoint_double hP', hp]
        simp [scalarStep, hb, add_nsmul, mul_nsmul, two_nsmul, nsmul_add, base]
    · simp only [affineChainStep, hb, Bool.false_eq_true, ↓reduceIte, Mmask8.testBit_or,
        Bool.or_eq_false_iff] at hclear
      obtain ⟨P, hr, hP', hp⟩ := hrel hclear.1
      refine ⟨G1.double P, ?_, G1.valid_double hP', ?_⟩
      · simpa only [affineChainStep, hb, Bool.false_eq_true, ↓reduceIte] using double_correct r l P hr hP' hclear.2
      · rw [G1.toPoint_double hP', hp]
        simp [scalarStep, hb, mul_nsmul, two_nsmul, nsmul_add]
  · intro _
    exact ⟨⟨x, y, Fp.one⟩, ⟨hx, hy, Fp8.holds_one l⟩, hP, (one_nsmul _).symm⟩

theorem times_z_correct (self : G1x8) (l : Fin 8) (P : G1)
    (h : self.Holds l P) (hP : G1.Valid P)
    (hu : self.times_z.2.toNat.testBit l = false) :
    ∃ Q, self.times_z.1.Holds l Q ∧ G1.Valid Q ∧ G1.toPoint Q = blsX • G1.toPoint P := by
  let base := G1.toPoint P
  have hfold := List.foldl_rel
    (fun (s : G1x8 × Mmask8) (n : ℕ) => s.2.toNat.testBit l = false →
      ∃ Q, s.1.Holds l Q ∧ G1.Valid Q ∧ G1.toPoint Q = n • base)
    (chainStep self) scalarStep ?_ (List.range Z_BITS[0]!).reverse (self, 0) 1 ?_
  · simpa only [times_z, scalarChain_eq] using hfold hu
  · rintro ⟨r, u⟩ n bit hrel hclear
    by_cases hb : is_lower_z_bit bit = true
    · simp only [chainStep, hb, ↓reduceIte, Mmask8.testBit_or,
        Bool.or_eq_false_iff] at hclear
      obtain ⟨Q, hr, hQ, hq⟩ := hrel hclear.1.1
      have hd := double_correct r l Q hr hQ hclear.1.2
      have hD := G1.valid_double hQ
      refine ⟨G1.add (G1.double Q) P, ?_, G1.valid_add hD hP, ?_⟩
      · simpa only [chainStep, hb, Bool.false_eq_true, ↓reduceIte] using
          add_correct r.double.1 self l (G1.double Q) P hd h hD hP hclear.2
      · rw [G1.toPoint_add hD hP, G1.toPoint_double hQ, hq]
        simp [scalarStep, hb, add_nsmul, mul_nsmul, two_nsmul, nsmul_add, base]
    · simp only [chainStep, hb, Bool.false_eq_true, ↓reduceIte, Mmask8.testBit_or,
        Bool.or_eq_false_iff] at hclear
      obtain ⟨Q, hr, hQ, hq⟩ := hrel hclear.1
      refine ⟨G1.double Q, ?_, G1.valid_double hQ, ?_⟩
      · simpa only [chainStep, hb, Bool.false_eq_true, ↓reduceIte] using double_correct r l Q hr hQ hclear.2
      · rw [G1.toPoint_double hQ, hq]
        simp [scalarStep, hb, mul_nsmul, two_nsmul, nsmul_add]
  · intro _
    exact ⟨P, h, hP, (one_nsmul _).symm⟩

theorem scott_membership_iff (px py : Fp8) (l : Fin 8) (x y : Fp)
    (hx : px.Holds l x) (hy : py.Holds l y) (hP : G1.Valid ⟨x, y, Fp.one⟩)
    (hu : (scott_membership px py).undecided.toNat.testBit l = false) :
    (scott_membership px py).members.toNat.testBit l = true ↔
      G1.inSubgroup ⟨x, y, Fp.one⟩ = true := by
  have hu' := hu
  simp only [scott_membership, Mmask8.testBit_or, Bool.or_eq_false_iff] at hu'
  obtain ⟨Q, hQ, hQV, hQP⟩ := times_z_affine_correct px py l x y hx hy hP hu'.1.1
  obtain ⟨T, hT, hTV, hTP⟩ := times_z_correct (times_z_affine px py).1 l Q hQ hQV hu'.1.2
  have hz : (T.z : ZMod Fp.modulus) ≠ 0 := by
    have h := (Holds.z hT).testBit_is_zero_mask
    rw [h, decide_eq_false_iff_not] at hu'
    exact hu'.2
  have hbeta : (Fp8.splat_limbs (.ofList BETA_MONT)).Holds l (beta : ZMod Fp.modulus) :=
    (Fp8.holds_splat_limbs (t := .ofList BETA_MONT)
      ⟨by decide, by decide +kernel⟩ l).of_eq (decode_of_val BETA_MONT_eq)
  have hxx := (Holds.x hT).testBit_eq_mask (((hx.mul hbeta).mul hbeta).mul (Holds.z hT).square)
  have hyy := (Holds.y hT).neg.testBit_eq_mask (hy.mul ((Holds.z hT).square.mul (Holds.z hT)))
  let vx : ZMod Fp.modulus := x
  let vy : ZMod Fp.modulus := y
  let tx : ZMod Fp.modulus := T.x
  let ty : ZMod Fp.modulus := T.y
  let tz : ZMod Fp.modulus := T.z
  let b : ZMod Fp.modulus := beta
  have hmember : (scott_membership px py).members.toNat.testBit l = true ↔
      tx = (vx * b * b) * tz ^ 2 ∧ -ty = vy * (tz ^ 2 * tz) := by
    simp only [scott_membership, Mmask8.testBit_and, Mmask8.testBit_not,
      Mmask8.testBit_or, hxx, hyy, hu'.1.1, hu'.1.2, hu'.2]
    simp
    rfl
  have hcompare :
      (tx = (vx * b * b) * tz ^ 2 ∧ -ty = vy * (tz ^ 2 * tz)) ↔
      G1Spec.sigma (G1Spec.sigma (G1.toPoint ⟨x, y, Fp.one⟩)) = -G1.toPoint T := by
    have hbase : G1.toPoint ⟨x, y, Fp.one⟩ = WeierstrassCurve.Affine.Point.some vx vy
        ((WeierstrassCurve.Jacobian.nonsingular_some vx vy).mp hP) :=
      WeierstrassCurve.Jacobian.Point.toAffine_some hP
    rw [hbase]
    simp only [G1Spec.sigma]
    rw [G1.toPoint, WeierstrassCurve.Jacobian.Point.toAffine_of_Z_ne_zero hTV hz,
      WeierstrassCurve.Affine.Point.neg_some, WeierstrassCurve.Affine.Point.some.injEq]
    change _ ↔ (b * (b * vx) = tx / tz ^ 2 ∧ vy = -(ty / tz ^ 3) - 0 * (tx / tz ^ 2) - 0)
    rw [zero_mul, sub_zero, sub_zero, ← neg_div,
      eq_div_iff (pow_ne_zero 2 hz), eq_div_iff (pow_ne_zero 3 hz), pow_succ _ 2]
    have heq : b * (b * vx) = vx * b * b := by ring
    rw [heq]
    exact and_congr eq_comm eq_comm
  rw [hmember, hcompare, G1Spec.inSubgroup_iff _ hP]
  have hscalar : G1.toPoint T = (LeanBlsSimd.z ^ 2) • G1.toPoint ⟨x, y, Fp.one⟩ := by
    rw [hTP, hQP, LeanBlsSimd.z, neg_sq, ← Nat.cast_pow, natCast_zsmul, pow_two, mul_nsmul]
  rw [hscalar, ← neg_smul]
  exact ⟨G1Spec.scott_sound _, G1Spec.scott_complete _⟩

end G1x8

end LeanBlsSimd
