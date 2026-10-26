import LeanBlsSimd.Refines.PointOperations
import LeanBlsSimd.Refines.UncompressG1

open Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls LeanBlsSimd
open EthLib.Cryptography.Bls

namespace LeanBlsSimd.Controls.PointOperations

theorem scalar_little_endian :
    PointOperations.scalar64 [1#u8, 2#u8, 3#u8, 4#u8, 5#u8, 6#u8, 7#u8, 8#u8] =
      0x0807060504030201 := by decide

theorem scalar_max : PointOperations.scalar64 (List.replicate 8 255#u8) = 2^64 - 1 := by
  decide

example : PointOperations.scalar64 (List.replicate 8 0#u8) = 0 := by decide
example : PointOperations.scalar64 (1#u8 :: List.replicate 7 0#u8) = 1 := by decide

example [PointOperationExternals] (h : PointOperations.OperationsMatchSpec) :
    ∃ result, g1_point.G1Point.weighted_sum ⟨[], by simp⟩ ⟨[], by simp⟩ = ok result ∧
      result = Kzg.g1Affine G1.zero ∧ Kzg.G1AffineValid result := by
  simpa [PointOperations.g1Sum] using
    PointOperations.g1_weighted_sum_eq_spec h ⟨[], by simp⟩ ⟨[], by simp⟩ (by simp) (by simp)

example [PointOperationExternals] (h : PointOperations.OperationsMatchSpec) :
    ∃ result, g2_point.G2Point.weighted_sum ⟨[], by simp⟩ ⟨[], by simp⟩ = ok result ∧
      result = Kzg.g2Affine G2.zero ∧ Kzg.G2AffineValid result := by
  simpa [PointOperations.g2Sum] using
    PointOperations.g2_weighted_sum_eq_spec h ⟨[], by simp⟩ ⟨[], by simp⟩ (by simp) (by simp)

example [RuntimeFeatures] [PointOperationExternals] (h : PointOperations.OperationsMatchSpec)
    (inputs : Slice (Array U8 48#usize)) (out result : Slice (Option g1_point.G1Point))
    (hlen : out.val.length = inputs.val.length)
    (hcall : uncompress_in_g1 inputs out = ok result)
    (p : g1_point.G1Point) (hp : some p ∈ result.val)
    (scalars : Slice U8) (hs : scalars.val.length = 8) :
    ∃ sum, g1_point.G1Point.weighted_sum ⟨[p], by scalar_tac⟩ scalars = ok sum ∧
      Kzg.G1AffineValid sum := by
  obtain ⟨actual, ha, _, hv⟩ := UncompressG1.uncompress_in_g1_eq_spec_list inputs out hlen
  have heq : actual = result := Result.ok.inj (ha.symm.trans hcall)
  subst result
  obtain ⟨sum, hsum, _, hvalid⟩ := PointOperations.g1_weighted_sum_eq_spec h
    ⟨[p], by scalar_tac⟩ scalars (by simpa using hs) (by simpa using hv p hp)
  exact ⟨sum, hsum, hvalid⟩

example [PointOperationExternals] (h : PointOperations.OperationsMatchSpec)
    (message dst : Slice U8) (scalars : Slice U8) (hs : scalars.val.length = 8) :
    ∃ hashed sum, g2_point.G2Point.hash_to_curve message dst = ok hashed ∧
      g2_point.G2Point.weighted_sum ⟨[hashed], by scalar_tac⟩ scalars = ok sum ∧
      Kzg.G2AffineValid sum := by
  obtain ⟨hashed, _, hh, _, _, hv⟩ := PointOperations.hash_to_curve_eq_spec h message dst
  obtain ⟨sum, hsum, _, hvalid⟩ := PointOperations.g2_weighted_sum_eq_spec h
    ⟨[hashed], by scalar_tac⟩ scalars (by simpa using hs) (by simpa using hv)
  exact ⟨hashed, sum, hh, hsum, hvalid⟩

end LeanBlsSimd.Controls.PointOperations
