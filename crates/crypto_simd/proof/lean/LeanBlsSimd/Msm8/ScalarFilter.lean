import LeanBlsSimd.Msm8.Infinity

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.Msm8

open EthCryptographySpecs Bls

theorem scalar_high_word (scalar : Array U64 4#usize)
    (h : Kzg.limbs scalar.val < 2 ^ 255) :
    scalar.val[3].val < 2 ^ 63 := by
  obtain ⟨a, b, c, d, hs⟩ := List.length_eq_four.mp scalar.property
  simp only [Kzg.limbs, hs, List.foldr_cons, List.foldr_nil] at h
  norm_num at h ⊢
  simpa only [hs] using (show d.val < 9223372036854775808 by omega)

theorem scalar_high_bit (scalar : Array U64 4#usize)
    (h : Kzg.limbs scalar.val < 2 ^ 255) :
    (scalar.val[3] >>> 63#i32 : Result U64) = ok 0#u64 := by
  have hs : scalar.val[3] >>> 63#i32 =
      ok (⟨scalar.val[3].bv.ushiftRight 63⟩ : U64) := rfl
  rw [hs]
  apply congrArg ok
  apply UScalar.eq_of_val_eq
  change (scalar.val[3].bv.ushiftRight 63).toNat = 0
  simp only [BitVec.ushiftRight_eq, BitVec.toNat_ushiftRight, Nat.shiftRight_eq_div_pow]
  exact Nat.div_eq_of_lt (scalar_high_word scalar h)

abbrev FilterScalar := Aeneas.Std.Array U64 4#usize

theorem keep_if_finite_refines (self : msm8.Msm8)
    (point : blst.blst_p1_affine) (scalar : FilterScalar)
    (hs : Kzg.limbs scalar.val < 2 ^ 255)
    (hp : Kzg.G1AffineValid point)
    (hpl : self.finite_points.val.length < Usize.max)
    (hsl : self.finite_scalars.val.length < Usize.max) :
    ∃ (ps : alloc.vec.Vec blst.blst_p1_affine) (ss : alloc.vec.Vec FilterScalar),
      msm8.Msm8.keep_if_finite self point scalar =
        ok { self with finite_points := ps, finite_scalars := ss } ∧
      ps.val = self.finite_points.val ++
        (if (Kzg.g1ReadAffine point).isInfinity then [] else [point]) ∧
      ss.val = self.finite_scalars.val ++
        (if (Kzg.g1ReadAffine point).isInfinity then [] else [scalar]) := by
  have hcall : msm8.Msm8.keep_if_finite self point scalar = (do
      let b ← msm8.is_infinity point
      if b then ok self else do
        let ps ← alloc.vec.Vec.push self.finite_points point
        let ss ← alloc.vec.Vec.push self.finite_scalars scalar
        ok { self with finite_points := ps, finite_scalars := ss }) := by
    rw [msm8.Msm8.keep_if_finite, index_usize_eq scalar 3#usize (by decide)]
    simp only [bind_tc_ok, UScalar.ofNatCore_val_eq, scalar_high_bit scalar hs]
    rfl
  rw [hcall, is_infinity_correct point hp]
  simp only [bind_tc_ok]
  by_cases hz : (Kzg.g1ReadAffine point).isInfinity = true
  · simp only [hz, if_true, List.append_nil]
    exact ⟨self.finite_points, self.finite_scalars, rfl, rfl, rfl⟩
  · simp only [hz, Bool.false_eq_true, if_false]
    obtain ⟨ps, hps, hpsval⟩ := WP.spec_imp_exists
      (alloc.vec.Vec.push_spec self.finite_points point hpl)
    obtain ⟨ss, hss, hssval⟩ := WP.spec_imp_exists
      (alloc.vec.Vec.push_spec self.finite_scalars scalar hsl)
    refine ⟨ps, ss, ?_, hpsval, hssval⟩
    rw [hps]
    simp only [bind_tc_ok, hss]

end LeanBlsSimd.Msm8
