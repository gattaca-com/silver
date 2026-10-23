import LeanBlsSimd.Kzg.Decoder
import LeanBlsSimd.Kzg.RepresentationLemmas
import LeanBlsSimd.Kzg.SetupBytes

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

/-- Independent spec-operation fixtures used only by mathematical mutation controls.
They are not instances of any generated runtime interface. -/
structure SpecOperations where
  uncompressG1 : Aeneas.Std.Array U8 48#usize → Option blst.blst_p1_affine
  uncompressG2 : Aeneas.Std.Array U8 96#usize → Option blst.blst_p2_affine
  frFromBytes : Aeneas.Std.Array U8 32#usize → Result (Option blst.blst_fr)
  frToBytes : blst.blst_fr → Result (Aeneas.Std.Array U8 32#usize)
  frFromU64 : U64 → Result blst.blst_fr
  frAdd : blst.blst_fr → blst.blst_fr → Result blst.blst_fr
  frSub : blst.blst_fr → blst.blst_fr → Result blst.blst_fr
  frMul : blst.blst_fr → blst.blst_fr → Result blst.blst_fr
  frInverse : blst.blst_fr → Result blst.blst_fr
  hashToFr : Slice U8 → Result blst.blst_fr
  g1ToAffine : blst.blst_p1 → Result blst.blst_p1_affine
  g1Add : blst.blst_p1 → blst.blst_p1 → Result blst.blst_p1
  g1Neg : blst.blst_p1 → Result blst.blst_p1
  g2Neg : blst.blst_p2_affine → Result blst.blst_p2_affine
  g1Lincomb : Slice blst.blst_p1_affine → Slice blst.blst_fr → Result blst.blst_p1
  pairingCheck : blst.blst_p1_affine → blst.blst_p2_affine →
    blst.blst_p1_affine → blst.blst_p2_affine → Result Bool

structure SpecOperationsCorrect (e : SpecOperations) : Prop where
  g2_decode : ∀ b,
    b = SetupPoints.g2Bytes0 ∨ b = SetupPoints.g2Bytes64 →
    ok (e.uncompressG2 b) = ok (specG2Verdict b)
  fr_bytes : ∀ b, e.frFromBytes b =
    ok ((Kzg.bytesToBlsField (arrayBytes b)).toOption.map frEncode)
  fr_u64 : ∀ x, e.frFromU64 x = ok (frEncode (Fr.ofNat x.val))
  fr_add : ∀ x y, e.frAdd (frEncode x) (frEncode y) = ok (frEncode (x + y))
  fr_sub : ∀ x y, e.frSub (frEncode x) (frEncode y) = ok (frEncode (x - y))
  fr_mul : ∀ x y, e.frMul (frEncode x) (frEncode y) = ok (frEncode (x * y))
  fr_inverse : ∀ x, x ≠ (0 : Fr) → e.frInverse (frEncode x) = ok (frEncode x.inverse)
  hash : ∀ b, e.hashToFr b = ok (frEncode (Fr.hashToBlsField (bytes b.val)))
  g1_affine : ∀ p, JacobianReduced p → G1Valid (g1ReadJacobian p) →
    e.g1ToAffine p = ok (g1Affine (g1ReadJacobian p))
  g1_add : ∀ p q, JacobianReduced p → JacobianReduced q →
    G1Valid (g1ReadJacobian p) → G1Valid (g1ReadJacobian q) →
    ∃ result, e.g1Add p q = ok result ∧
      G1Rep result (G1.add (g1ReadJacobian p) (g1ReadJacobian q))
  g1_neg : ∀ p, JacobianReduced p → G1Valid (g1ReadJacobian p) →
    ∃ result, e.g1Neg p = ok result ∧ G1Rep result (G1.neg (g1ReadJacobian p))
  g2_neg : ∀ p, G2AffineValid p → e.g2Neg p = ok (g2Affine (G2.neg (g2ReadAffine p)))
  lincomb : ∀ ps fs,
    ps.val.length = fs.val.length →
    (∀ p ∈ ps.val, G1AffineValid p) → (∀ f ∈ fs.val, FrReduced f) →
    ∃ result, e.g1Lincomb ps fs = ok result ∧
      G1Rep result (G1.msm (ps.val.map g1ReadAffine).toArray (fs.val.map frRead).toArray)
  pairing : ∀ p q p' q',
    G1AffineValid p → G2AffineValid q → G1AffineValid p' → G2AffineValid q' →
    e.pairingCheck p q p' q' =
      ok (Bls.pairingCheck #[(g1ReadAffine p, g2ReadAffine q),
        (g1ReadAffine p', g2ReadAffine q')])

def SpecFrToBytesCorrect (e : SpecOperations) : Prop :=
  ∀ x, ∃ result, e.frToBytes (frEncode x) = ok result ∧
    arrayBytes result = Kzg.blsFieldToBytes x

def SpecG1DecoderCorrect (e : SpecOperations) : Prop :=
  ∀ b, e.uncompressG1 b = specVerdict b

def SpecG2DecoderCorrect (e : SpecOperations) : Prop :=
  ∀ b, e.uncompressG2 b = specG2Verdict b

def SpecModelCorrect (e : SpecOperations) : Prop :=
  SpecOperationsCorrect e ∧ SpecG1DecoderCorrect e

def specFrBytes (x : Fr) : Aeneas.Std.Array U8 32#usize :=
  ⟨x.toBytesBE.data.toList.map (fun b => ⟨b.toBitVec⟩), by simp [Fr.toBytesBE]⟩

@[reducible] def specExternals : SpecOperations where
  uncompressG1 := UncompressG1.specVerdict
  uncompressG2 := UncompressG2.specVerdict
  frFromBytes b := ok ((Kzg.bytesToBlsField (arrayBytes b)).toOption.map frEncode)
  frToBytes x := ok (specFrBytes (frRead x))
  frFromU64 x := ok (frEncode (Fr.ofNat x.val))
  frAdd x y := ok (frEncode (frRead x + frRead y))
  frSub x y := ok (frEncode (frRead x - frRead y))
  frMul x y := ok (frEncode (frRead x * frRead y))
  frInverse x := ok (frEncode (frRead x).inverse)
  hashToFr b := ok (frEncode (Fr.hashToBlsField (bytes b.val)))
  g1ToAffine p := ok (g1Affine (g1ReadJacobian p))
  g1Add p q := ok (g1Jacobian (G1.add (g1ReadJacobian p) (g1ReadJacobian q)))
  g1Neg p := ok (g1Jacobian (G1.neg (g1ReadJacobian p)))
  g2Neg p := ok (g2Affine (G2.neg (g2ReadAffine p)))
  g1Lincomb ps fs :=
    if ps.val.length = fs.val.length then
      ok (g1Jacobian (G1.msm (ps.val.map g1ReadAffine).toArray (fs.val.map frRead).toArray))
    else fail .panic
  pairingCheck p q p' q' :=
    ok (Bls.pairingCheck #[(g1ReadAffine p, g2ReadAffine q), (g1ReadAffine p', g2ReadAffine q')])

theorem specExternals_correct :
    SpecOperationsCorrect specExternals ∧
    SpecG1DecoderCorrect specExternals ∧
    SpecG2DecoderCorrect specExternals := by
  refine ⟨?_, ?_, ?_⟩
  · constructor
    · intro b _
      change ok (UncompressG2.specVerdict b) = ok (specG2Verdict b)
      rw [specG2Verdict_eq_bls]
    · intro b
      rfl
    · intro x
      rfl
    · intro x y
      change ok (frEncode (frRead (frEncode x) + frRead (frEncode y))) = _
      rw [frRead_frEncode, frRead_frEncode]
    · intro x y
      change ok (frEncode (frRead (frEncode x) - frRead (frEncode y))) = _
      rw [frRead_frEncode, frRead_frEncode]
    · intro x y
      change ok (frEncode (frRead (frEncode x) * frRead (frEncode y))) = _
      rw [frRead_frEncode, frRead_frEncode]
    · intro x _
      change ok (frEncode (frRead (frEncode x)).inverse) = _
      rw [frRead_frEncode]
    · intro b
      rfl
    · intro p _ _
      rfl
    · intro p q _ _ _ _
      exact ⟨_, rfl, g1Jacobian_rep _⟩
    · intro p _ _
      exact ⟨_, rfl, g1Jacobian_rep _⟩
    · intro p _
      rfl
    · intro ps fs hlen _ _
      refine ⟨_, ?_, g1Jacobian_rep _⟩
      change (if ps.val.length = fs.val.length then _ else _) = _
      rw [if_pos hlen]
    · intro p q p' q' _ _ _ _
      rfl
  · intro b
    exact (specVerdict_eq_bls b).symm
  · intro b
    exact (specG2Verdict_eq_bls b).symm

theorem specExternals_contract : SpecModelCorrect specExternals :=
  ⟨specExternals_correct.1, specExternals_correct.2.1⟩

theorem specExternals_fr_to_bytes_correct : SpecFrToBytesCorrect specExternals := by
  intro x
  refine ⟨specFrBytes x, ?_, ?_⟩
  · change ok (specFrBytes (frRead (frEncode x))) = _
    rw [frRead_frEncode]
  · apply ByteArray.ext
    simp only [arrayBytes, bytes, specFrBytes, Kzg.blsFieldToBytes, List.map_map,
      Function.comp_def, U8.bv, UInt8.ofBitVec_toBitVec, List.map_id_fun', id_eq,
      _root_.Array.toArray_toList]

end LeanBlsSimd.Kzg
