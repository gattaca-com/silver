import LeanBlsSimd.Portable.G1.Scott

open EthLib.Cryptography Bls
open WeierstrassCurve

namespace LeanBlsSimd.Portable.G1
set_option maxRecDepth 4096
set_option exponentiation.threshold 4096

private theorem affine_ne_zero (x y : ZMod Bls.Fp.modulus) (hp : Bls.G1.Valid ⟨x,y,Bls.Fp.one⟩) :
    Bls.G1.toPoint ⟨x,y,Bls.Fp.one⟩ ≠ 0 := by
  have he : Bls.G1.toPoint ⟨x,y,Bls.Fp.one⟩ =
      Affine.Point.some x y ((Jacobian.nonsingular_some x y).mp hp) :=
    Jacobian.Point.toAffine_some hp
  rw [he]
  exact Affine.Point.some_ne_zero _

private theorem coprime_torsion (x y : Bls.Fp) (hp : Bls.G1.Valid ⟨x,y,Bls.Fp.one⟩)
    (n : Nat) (hc : n.Coprime Bls.Fr.modulus) (hn : n • Bls.G1.toPoint ⟨x,y,Bls.Fp.one⟩ = 0) :
    Bls.G1.inSubgroup ⟨x,y,Bls.Fp.one⟩ = false := by
  apply Bool.eq_false_iff.mpr
  intro hmem
  have hr := (G1Spec.inSubgroup_iff _ hp).mp hmem
  have hdn := addOrderOf_dvd_iff_nsmul_eq_zero.mpr hn
  have hdr := addOrderOf_dvd_iff_nsmul_eq_zero.mpr hr
  have hd : addOrderOf (Bls.G1.toPoint ⟨x,y,Bls.Fp.one⟩) ∣ 1 := by
    simpa only [hc.gcd_eq_one] using Nat.dvd_gcd hdn hdr
  exact affine_ne_zero x y hp (AddMonoid.addOrderOf_eq_one_iff.mp (Nat.dvd_one.mp hd))

theorem y_zero_not_in_subgroup (x : Bls.Fp) (hp : Bls.G1.Valid ⟨x,0,Bls.Fp.one⟩) :
    Bls.G1.inSubgroup ⟨x,0,Bls.Fp.one⟩ = false := by
  have he : Bls.G1.neg ⟨x,0,Bls.Fp.one⟩ = ⟨x,0,Bls.Fp.one⟩ := by
    change (⟨x,-(0 : ZMod Bls.Fp.modulus),Bls.Fp.one⟩ : Bls.G1) = _
    rw [neg_zero]
    rfl
  have hn : -Bls.G1.toPoint ⟨x,0,Bls.Fp.one⟩ = Bls.G1.toPoint ⟨x,0,Bls.Fp.one⟩ := by
    rw [←Bls.G1.toPoint_neg hp,he]
  apply coprime_torsion x 0 hp 2 (by decide +kernel)
  rw [two_nsmul]
  conv_lhs => arg 2; rw [←hn]
  exact add_neg_cancel _

theorem x_zero_order_three (y : ZMod Bls.Fp.modulus) (hp : Bls.G1.Valid ⟨0,y,Bls.Fp.one⟩) :
    3 • Bls.G1.toPoint ⟨0,y,Bls.Fp.one⟩ = 0 := by
  have hy : y^2 = (2 : ZMod Bls.Fp.modulus)^2 := by
    have h := (G1Spec.nonsingular_iff 0 y).mp (Jacobian.nonsingular_some 0 y |>.mp hp)
    norm_num at h ⊢
    exact h
  rcases eq_or_eq_neg_of_sq_eq_sq y 2 hy with rfl | rfl
  · rw [←Bls.G1.toPoint_mulNat hp 3]
    apply Jacobian.Point.toAffine_of_Z_eq_zero
    decide +kernel
  · rw [←Bls.G1.toPoint_mulNat hp 3]
    apply Jacobian.Point.toAffine_of_Z_eq_zero
    decide +kernel

theorem x_zero_not_in_subgroup (y : Bls.Fp) (hp : Bls.G1.Valid ⟨0,y,Bls.Fp.one⟩) :
    Bls.G1.inSubgroup ⟨0,y,Bls.Fp.one⟩ = false :=
  coprime_torsion 0 y hp 3 (by decide +kernel) (x_zero_order_three y hp)

end LeanBlsSimd.Portable.G1
