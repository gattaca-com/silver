import LeanBlsSimd.Kzg.PointValidity
import EthLib.Cryptography.Bls.HashToCurve

open Aeneas.Std Result
open EthLib.Cryptography.Bls
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.PointOperations

def scalar64 (bytes : List U8) : Nat :=
  bytes.foldr (fun byte acc => byte.val + 256 * acc) 0

def g1Sum : List g1_point.G1Point → List U8 → G1
  | [], _ => G1.zero
  | p :: ps, scalars =>
    G1.add (G1.mulNat (Kzg.g1ReadAffine p) (scalar64 (scalars.take 8)))
      (g1Sum ps (scalars.drop 8))

def g2Sum : List g2_point.G2Point → List U8 → G2
  | [], _ => G2.zero
  | p :: ps, scalars =>
    G2.add (G2.mulNat (Kzg.g2ReadAffine p) (scalar64 (scalars.take 8)))
      (g2Sum ps (scalars.drop 8))

/-- Trusted blst operations, including canonical subgroup output. -/
structure OperationsMatchSpec [PointOperationExternals] : Prop where
  negativeG1 : PointOperationExternals.negativeG1 = Kzg.g1Affine (G1.neg G1.generator) ∧
    Kzg.G1AffineValid PointOperationExternals.negativeG1
  hashG2 : ∀ (message dst : Slice U8), ∃ p,
    HashToCurve.hashToG2 (Kzg.bytes message.val) (Kzg.bytes dst.val) = .ok p ∧
    PointOperationExternals.hashG2 message dst = Kzg.g2Affine p ∧
    Kzg.G2AffineValid (PointOperationExternals.hashG2 message dst)
  sumG1 : ∀ (points : Slice g1_point.G1Point) (scalars : Slice U8),
    scalars.val.length = points.val.length * 8 →
    (∀ p ∈ points.val, Kzg.G1AffineValid p) →
    PointOperationExternals.sumG1 points scalars = Kzg.g1Affine (g1Sum points.val scalars.val) ∧
    Kzg.G1AffineValid (PointOperationExternals.sumG1 points scalars)
  sumG2 : ∀ (points : Slice g2_point.G2Point) (scalars : Slice U8),
    scalars.val.length = points.val.length * 8 →
    (∀ p ∈ points.val, Kzg.G2AffineValid p) →
    PointOperationExternals.sumG2 points scalars = Kzg.g2Affine (g2Sum points.val scalars.val) ∧
    Kzg.G2AffineValid (PointOperationExternals.sumG2 points scalars)

theorem negative_generator_eq_spec [PointOperationExternals] (h : OperationsMatchSpec) :
    ∃ result, g1_point.G1Point.negative_generator = ok result ∧
      result = Kzg.g1Affine (G1.neg G1.generator) ∧ Kzg.G1AffineValid result :=
  ⟨_, rfl, h.negativeG1⟩

theorem hash_to_curve_eq_spec [PointOperationExternals] (h : OperationsMatchSpec)
    (message dst : Slice U8) :
    ∃ result p, g2_point.G2Point.hash_to_curve message dst = ok result ∧
      HashToCurve.hashToG2 (Kzg.bytes message.val) (Kzg.bytes dst.val) = .ok p ∧
      result = Kzg.g2Affine p ∧ Kzg.G2AffineValid result := by
  obtain ⟨p, hp⟩ := h.hashG2 message dst
  exact ⟨_, p, rfl, hp⟩

theorem g1_weighted_sum_eq_spec [PointOperationExternals] (h : OperationsMatchSpec)
    (points : Slice g1_point.G1Point) (scalars : Slice U8)
    (hlen : scalars.val.length = points.val.length * 8)
    (hv : ∀ p ∈ points.val, Kzg.G1AffineValid p) :
    ∃ result, g1_point.G1Point.weighted_sum points scalars = ok result ∧
      result = Kzg.g1Affine (g1Sum points.val scalars.val) ∧ Kzg.G1AffineValid result := by
  exact ⟨_, by simp [g1_point.G1Point.weighted_sum, hlen], h.sumG1 points scalars hlen hv⟩

theorem g2_weighted_sum_eq_spec [PointOperationExternals] (h : OperationsMatchSpec)
    (points : Slice g2_point.G2Point) (scalars : Slice U8)
    (hlen : scalars.val.length = points.val.length * 8)
    (hv : ∀ p ∈ points.val, Kzg.G2AffineValid p) :
    ∃ result, g2_point.G2Point.weighted_sum points scalars = ok result ∧
      result = Kzg.g2Affine (g2Sum points.val scalars.val) ∧ Kzg.G2AffineValid result := by
  exact ⟨_, by simp [g2_point.G2Point.weighted_sum, hlen], h.sumG2 points scalars hlen hv⟩

theorem g1_weighted_sum_length_mismatch [PointOperationExternals]
    (points : Slice g1_point.G1Point) (scalars : Slice U8)
    (hlen : scalars.val.length ≠ points.val.length * 8) :
    g1_point.G1Point.weighted_sum points scalars = fail .assertionFailure := by
  simp [g1_point.G1Point.weighted_sum, hlen]

theorem g2_weighted_sum_length_mismatch [PointOperationExternals]
    (points : Slice g2_point.G2Point) (scalars : Slice U8)
    (hlen : scalars.val.length ≠ points.val.length * 8) :
    g2_point.G2Point.weighted_sum points scalars = fail .assertionFailure := by
  simp [g2_point.G2Point.weighted_sum, hlen]

end LeanBlsSimd.PointOperations
