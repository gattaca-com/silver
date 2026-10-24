import LeanBlsSimd.Portable.G1.PairScott

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.G1.Pair.Controls
set_option maxRecDepth 4096
set_option exponentiation.threshold 4096

private abbrev g := Bls.G1.generator
private theorem generator_member : Bls.G1.inSubgroup g = true :=
  (G1Spec.inSubgroup_iff _ Bls.G1.valid_generator).mpr Bls.G1.modulus_smul_generator

theorem only_equal_lane_is_exceptional [RuntimeFeatures] :
    (do let (_,e) ← portable.g1_pair.G1Pair.add_affine (encode g (Bls.G1.double g))
          (fields g.x g.x) (fields g.y g.y)
        ok e) = ok (flags true false) := by
  rw [add_affine_encoded]
  have he : affineExceptional g g.x g.y = true := by decide +kernel
  have hn : affineExceptional (Bls.G1.double g) g.x g.y = false := by decide +kernel
  simp only [bind_tc_ok,he,hn]
  rfl

theorem one_flagged_lane_recomputed [RuntimeFeatures] :
    portable.g1_pair.G1Pair.in_g1_loop2 (fields g.x g.x) (fields g.y g.y)
      (flags true false) (encode Bls.G1.zero (G1.timesZ (G1.timesZ g))) (flags false false) 0#usize =
      ok (flags true true) := by
  have h := finish_encoded g.x g.x g.y g.y (true,Bls.G1.zero) (false,G1.timesZ (G1.timesZ g))
    Bls.G1.valid_generator Bls.G1.valid_generator (by simp) (by intro _; rfl)
  have he : (⟨g.x,g.y,Bls.Fp.one⟩ : Bls.G1) = g := rfl
  simpa only [he,generator_member] using h

theorem flagged_infinity_requires_fallback [RuntimeFeatures] :
    portable.g1.G1.is_minus_sigma_squared (G1.encode Bls.G1.zero)
      (Kzg.fpEncode g.x).l (Kzg.fpEncode g.y).l ≠ ok true := by
  rw [G1.is_minus_sigma_squared_fields]
  have aux (x y : ZMod Bls.Fp.modulus) : G1.comparisonBool 1 1 0 x y = false := by
    simp only [G1.comparisonBool,G1.scottComparison,ne_self_iff_false,false_and,decide_false]
  have h : G1.comparisonBool Bls.G1.zero.x Bls.G1.zero.y Bls.G1.zero.z g.x g.y = false := aux _ _
  rw [h]
  intro he
  cases Result.ok.inj he

theorem pair_accepts_generators [RuntimeFeatures] :
    portable.g1_pair.G1Pair.in_g1 (fields g.x g.x) (fields g.y g.y) = ok (flags true true) := by
  have h := in_g1_encoded g.x g.x g.y g.y Bls.G1.valid_generator Bls.G1.valid_generator
  have he : (⟨g.x,g.y,Bls.Fp.one⟩ : Bls.G1) = g := rfl
  simpa only [he,generator_member] using h

#print axioms add_encoded
#print axioms add_affine_encoded
#print axioms affine_loop_encoded
#print axioms projective_loop_encoded
#print axioms finish_encoded
#print axioms in_g1_encoded

end LeanBlsSimd.Portable.G1.Pair.Controls
