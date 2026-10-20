import LeanBlsSimd.Kzg.Extender.Kernel.Fr8AddSub
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Mul

open Aeneas Aeneas.Std Result
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg
open scoped EthCryptographySpecs.Bls.Fr

namespace LeanBlsSimd.Kzg.Extender.Kernel

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
