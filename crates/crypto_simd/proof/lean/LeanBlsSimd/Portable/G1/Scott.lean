import LeanBlsSimd.Portable.G1.Chains
import LeanBlsSimd.Portable.Fp.Sign
import LeanBlsSimd.Portable.Fp.Equality
import LeanBlsSimd.Spec.G1Curve

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.G1
set_option maxRecDepth 4096
set_option exponentiation.threshold 4096

theorem beta_encoded : portable.constants.BETA = (Kzg.fpEncode (beta : ZMod Bls.Fp.modulus)).l := by
  unfold portable.constants.BETA
  apply Subtype.ext
  decide +kernel

private theorem is_zero_field (x : ZMod Bls.Fp.modulus) :
    portable.fp.Fp.is_zero (Kzg.fpEncode x).l = ok (decide (x=0)) := by
  rw [Fp.is_zero_encoded]
  congr 1
  apply Bool.eq_iff_iff.mpr
  simp only [decide_eq_true_eq]
  exact Bls.G1.isZero_iff

private theorem mul_field [RuntimeFeatures] (x y : ZMod Bls.Fp.modulus) :
    portable.fp.Fp.mul (Kzg.fpEncode x).l (Kzg.fpEncode y).l = ok (Kzg.fpEncode (x*y)).l :=
  Fp.mul_encoded x y

private theorem square_field [RuntimeFeatures] (x : ZMod Bls.Fp.modulus) :
    portable.fp.Fp.square (Kzg.fpEncode x).l = ok (Kzg.fpEncode (x*x)).l := Fp.square_encoded x

private theorem neg_field (x : ZMod Bls.Fp.modulus) :
    portable.fp.Fp.neg (Kzg.fpEncode x).l = ok (Kzg.fpEncode (-x)).l := Fp.neg_encoded x

private theorem eq_field (x y : ZMod Bls.Fp.modulus) :
    portable.fp.Fp.Insts.CoreCmpPartialEqFp.eq (Kzg.fpEncode x).l (Kzg.fpEncode y).l =
      ok (decide (x=y)) := Fp.eq_encoded x y

abbrev scottComparison (tx ty tz x y : ZMod Bls.Fp.modulus) : Prop :=
  tz ≠ 0 ∧ tx = (x*beta*beta)*(tz*tz) ∧ -ty = y*((tz*tz)*tz)

def comparisonBool (tx ty tz x y : ZMod Bls.Fp.modulus) : Bool :=
  decide (scottComparison tx ty tz x y)

theorem is_minus_sigma_squared_fields [RuntimeFeatures] (T : Bls.G1) (x y : ZMod Bls.Fp.modulus) :
    portable.g1.G1.is_minus_sigma_squared (encode T) (Kzg.fpEncode x).l (Kzg.fpEncode y).l =
      ok (comparisonBool T.x T.y T.z x y) := by
  let tx : ZMod Bls.Fp.modulus := T.x
  let ty : ZMod Bls.Fp.modulus := T.y
  let tz : ZMod Bls.Fp.modulus := T.z
  simp only [portable.g1.G1.is_minus_sigma_squared,portable.g1.G1.is_infinity,encode,
    beta_encoded,is_zero_field,square_field,mul_field,neg_field,eq_field,bind_tc_ok]
  change (if decide (tz=0) then ok false else
    if decide (tx=(x*beta*beta)*(tz*tz)) then ok (decide (-ty=y*((tz*tz)*tz))) else ok false) = _
  change _ = ok (decide (scottComparison tx ty tz x y))
  unfold scottComparison
  by_cases hz : tz = 0
  · simp only [hz,decide_true,if_true,ne_self_iff_false,false_and,decide_false]
  · simp only [hz,decide_false,Bool.false_eq_true,if_false]
    split <;> simp_all

private theorem comparison_iff (T : Bls.G1) (x y : Bls.Fp) (hT : Bls.G1.Valid T)
    (hp : Bls.G1.Valid ⟨x,y,Bls.Fp.one⟩) :
    scottComparison T.x T.y T.z x y ↔
      G1Spec.sigma (G1Spec.sigma (Bls.G1.toPoint ⟨x,y,Bls.Fp.one⟩)) = -Bls.G1.toPoint T := by
  let tx : ZMod Bls.Fp.modulus := T.x
  let ty : ZMod Bls.Fp.modulus := T.y
  let tz : ZMod Bls.Fp.modulus := T.z
  let vx : ZMod Bls.Fp.modulus := x
  let vy : ZMod Bls.Fp.modulus := y
  let b : ZMod Bls.Fp.modulus := beta
  change scottComparison tx ty tz vx vy ↔ _
  unfold scottComparison
  have hbase : Bls.G1.toPoint ⟨x,y,Bls.Fp.one⟩ = WeierstrassCurve.Affine.Point.some vx vy
      ((WeierstrassCurve.Jacobian.nonsingular_some vx vy).mp hp) :=
    WeierstrassCurve.Jacobian.Point.toAffine_some hp
  by_cases hz : tz = 0
  · have ht0 : Bls.G1.toPoint T = 0 := WeierstrassCurve.Jacobian.Point.toAffine_of_Z_eq_zero hz
    rw [hbase,ht0]
    simp only [hz,ne_self_iff_false,false_and,G1Spec.sigma,neg_zero]
    exact iff_of_false False.elim (WeierstrassCurve.Affine.Point.some_ne_zero _)
  · rw [hbase]
    simp only [G1Spec.sigma]
    rw [Bls.G1.toPoint,WeierstrassCurve.Jacobian.Point.toAffine_of_Z_ne_zero hT hz,
      WeierstrassCurve.Affine.Point.neg_some,WeierstrassCurve.Affine.Point.some.injEq]
    change _ ↔ (b*(b*vx) = tx/tz^2 ∧ vy = -(ty/tz^3)-0*(tx/tz^2)-0)
    rw [zero_mul,sub_zero,sub_zero,←neg_div,
      eq_div_iff (pow_ne_zero 2 hz),eq_div_iff (pow_ne_zero 3 hz),pow_succ _ 2]
    have heq : b*(b*vx) = vx*b*b := by ring
    rw [heq]
    simp only [←sq]
    exact (and_iff_right hz).trans (and_congr eq_comm eq_comm)

theorem is_minus_sigma_squared_spec [RuntimeFeatures] (T : Bls.G1) (x y : Bls.Fp)
    (hT : Bls.G1.Valid T) (hp : Bls.G1.Valid ⟨x,y,Bls.Fp.one⟩) :
    portable.g1.G1.is_minus_sigma_squared (encode T) (Kzg.fpEncode x).l (Kzg.fpEncode y).l =
      ok (decide (G1Spec.sigma (G1Spec.sigma (Bls.G1.toPoint ⟨x,y,Bls.Fp.one⟩)) =
        -Bls.G1.toPoint T)) := by
  rw [is_minus_sigma_squared_fields]
  congr 1
  apply Bool.eq_iff_iff.mpr
  simp only [comparisonBool,decide_eq_true_eq]
  exact comparison_iff T x y hT hp

theorem in_g1_encoded [RuntimeFeatures] (x y : Bls.Fp) (hp : Bls.G1.Valid ⟨x,y,Bls.Fp.one⟩) :
    portable.g1.G1.in_g1 (Kzg.fpEncode x).l (Kzg.fpEncode y).l =
      ok (Bls.G1.inSubgroup ⟨x,y,Bls.Fp.one⟩) := by
  let P : Bls.G1 := ⟨x,y,Bls.Fp.one⟩
  obtain ⟨hq,hqp⟩ := timesZ_valid_point P hp
  obtain ⟨ht,htp⟩ := timesZ_valid_point (timesZ P) hq
  have hscalar : Bls.G1.toPoint (timesZ (timesZ P)) =
      (LeanBlsSimd.z^2) • Bls.G1.toPoint P := by
    rw [htp,hqp,LeanBlsSimd.z,neg_sq,←Nat.cast_pow,natCast_zsmul,pow_two,mul_nsmul]
  simp only [portable.g1.G1.in_g1,times_z_affine_encoded,times_z_encoded,bind_tc_ok]
  rw [is_minus_sigma_squared_spec _ x y ht hp]
  congr 1
  apply Bool.eq_iff_iff.mpr
  rw [decide_eq_true_eq,G1Spec.inSubgroup_iff _ hp,hscalar,←neg_smul]
  exact ⟨G1Spec.scott_sound _,G1Spec.scott_complete _⟩

end LeanBlsSimd.Portable.G1
