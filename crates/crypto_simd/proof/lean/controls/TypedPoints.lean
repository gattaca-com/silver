import LeanBlsSimd.Refines.CheckedPoints
import LeanBlsSimd.Refines.UncompressG1
import LeanBlsSimd.Refines.UncompressG2

open Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls LeanBlsSimd

@[reducible] noncomputable def pointSpecExternals : PointExternals :=
  ⟨CheckedPoints.g1Spec, CheckedPoints.g2Spec⟩

example : @CheckedPoints.ConstructorsMatchSpec pointSpecExternals := by
  letI : PointExternals := pointSpecExternals
  exact ⟨fun _ => rfl, fun _ => rfl⟩

private def zeroFp : blst.blst_fp :=
  ⟨Array.make 6#usize (List.replicate 6 0#u64) (by rfl)⟩

private def zeroFp2 : blst.blst_fp2 :=
  ⟨Array.make 2#usize [zeroFp, zeroFp] (by rfl)⟩

example : Kzg.G1AffineValid ⟨zeroFp, zeroFp⟩ :=
  Kzg.g1_verdict_valid _ _ G1Spec.infinity_verdict

example : Kzg.G2AffineValid ⟨zeroFp2, zeroFp2⟩ :=
  Kzg.g2_verdict_valid _ _ G2Spec.infinity_verdict

example [RuntimeFeatures] [KzgExternals] [UncompressG1.FallbackCorrect] (inputs : Slice (Array U8 48#usize))
    (out result : Slice (Option g1_point.G1Point))
    (hlen : out.val.length = inputs.val.length)
    (hcall : uncompress_in_g1 inputs out = ok result)
    (p : g1_point.G1Point) (hp : some p ∈ result.val) : Kzg.G1AffineValid p := by
  obtain ⟨actual, ha, _, hv⟩ := UncompressG1.uncompress_in_g1_eq_spec_list inputs out hlen
  have heq : actual = result := Result.ok.inj (ha.symm.trans hcall)
  subst result
  exact hv p hp

example [RuntimeFeatures] [BlsExternals] (hblst : UncompressG2.BlstMatchesSpec)
    (inputs : Slice (Array U8 96#usize)) (out result : Slice (Option g2_point.G2Point))
    (hlen : out.val.length = inputs.val.length)
    (hcall : uncompress_in_g2 inputs out = ok result)
    (p : g2_point.G2Point) (hp : some p ∈ result.val) : Kzg.G2AffineValid p := by
  obtain ⟨actual, ha, _, hv⟩ := UncompressG2.uncompress_in_g2_eq_spec_list hblst inputs out hlen
  have heq : actual = result := Result.ok.inj (ha.symm.trans hcall)
  subst result
  exact hv p hp

example [PointExternals] (h : CheckedPoints.ConstructorsMatchSpec)
    (raw : blst.blst_p1_affine) (hp : ¬ Kzg.G1AffineValid raw) :
    g1_point.G1Point.from_blst raw = ok none := by
  simp [g1_point.G1Point.from_blst, h.g1, CheckedPoints.g1Spec, hp]

example [PointExternals] (h : CheckedPoints.ConstructorsMatchSpec)
    (raw : blst.blst_p2_affine) (hp : ¬ Kzg.G2AffineValid raw) :
    g2_point.G2Point.from_blst raw = ok none := by
  simp [g2_point.G2Point.from_blst, h.g2, CheckedPoints.g2Spec, hp]

example (raw : blst.blst_p1_affine) :
    g1_point.G1Point.from_subgroup_unchecked raw = ok raw := rfl

example (raw : blst.blst_p2_affine) :
    g2_point.G2Point.from_subgroup_unchecked raw = ok raw := rfl
