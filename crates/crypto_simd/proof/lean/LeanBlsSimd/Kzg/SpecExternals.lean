import LeanBlsSimd.Kzg.Decoder
import LeanBlsSimd.Kzg.RepresentationLemmas

open Aeneas Aeneas.Std Result
open EthCryptographySpecs Bls
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

@[reducible] def specExternals : KzgExternals where
  simdAvailable := false
  uncompressG1 := UncompressG1.specVerdict
  uncompressG2 := UncompressG2.specVerdict
  frFromBytes b := ok ((Kzg.bytesToBlsField (arrayBytes b)).toOption.map frEncode)
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
  g1Lincomb ps fs scratch :=
    if ps.val.length = fs.val.length then
      ok (g1Jacobian (G1.msm (ps.val.map g1ReadAffine).toArray (fs.val.map frRead).toArray), scratch)
    else fail .panic
  pairingCheck p q p' q' :=
    ok (Bls.pairingCheck #[(g1ReadAffine p, g2ReadAffine q), (g1ReadAffine p', g2ReadAffine q')])

theorem specExternals_correct :
    BlstCorrect specExternals ∧
    @UncompressG1.BlstMatchesSpec specExternals.toBlsExternals ∧
    @UncompressG2.BlstMatchesSpec specExternals.toBlsExternals := by
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
    · intro ps fs scratch hlen _ _
      refine ⟨_, scratch, ?_, g1Jacobian_rep _⟩
      change (if ps.val.length = fs.val.length then _ else _) = _
      rw [if_pos hlen]
    · intro p q p' q' _ _ _ _
      rfl
  · intro b
    rfl
  · intro b
    rfl

theorem specExternals_contract : ExternalsCorrect specExternals :=
  @externalsCorrect_of_blstMatchesSpec specExternals
    specExternals_correct.1 specExternals_correct.2.1

end LeanBlsSimd.Kzg
