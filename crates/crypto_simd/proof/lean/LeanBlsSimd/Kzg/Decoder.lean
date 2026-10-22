import LeanBlsSimd.Kzg.FpEncoding
import LeanBlsSimd.Kzg.Externals
import LeanBlsSimd.Refines.UncompressG1
import LeanBlsSimd.Refines.UncompressG2

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

set_option exponentiation.threshold 512
set_option maxRecDepth 2048


private theorem g1Affine_eq_bls (p : EthCryptographySpecs.Bls.G1) :
    g1Affine p = DecompressG1.toBlstP1Affine (G1Spec.blstLimbs p) := by
  simp [g1Affine, DecompressG1.toBlstP1Affine, G1Spec.blstLimbs, fpEncode_eq_bls]

theorem specVerdict_eq_bls (b : Array U8 48#usize) :
    specVerdict b = UncompressG1.specVerdict b := by
  unfold specVerdict specPoint UncompressG1.specVerdict G1Spec.verdict
  change ((EthCryptographySpecs.Kzg.bytesToKzgProof (arrayBytes b)).toOption.bind
    (fun validated => (EthCryptographySpecs.Bls.G1.uncompress validated).toOption)).map _ = _
  have hb : G1Spec.toBytes (ofArray ofU8 b) = arrayBytes b := rfl
  rw [hb]
  cases EthCryptographySpecs.Kzg.bytesToKzgProof (arrayBytes b) with
  | error e => rfl
  | ok validated =>
    dsimp only [Except.toOption, Option.bind]
    cases EthCryptographySpecs.Bls.G1.uncompress validated with
    | error e => rfl
    | ok p => exact congrArg some (g1Affine_eq_bls p)

theorem g1DecoderCorrect_of_blstMatchesSpec [e : KzgExternals]
    (hg1 : UncompressG1.BlstMatchesSpec) : G1DecoderCorrect e := by
  intro inputs out hlen
  have hv : specVerdict = UncompressG1.specVerdict := funext specVerdict_eq_bls
  simpa only [hv] using
    UncompressG1.uncompress_in_g1_eq_spec_list hg1 inputs out hlen

theorem externalsCorrect_of_blstMatchesSpec [e : KzgExternals]
    (hblst : BlstCorrect e) (hg1 : UncompressG1.BlstMatchesSpec) :
    ExternalsCorrect e := by
  exact ⟨hblst, g1DecoderCorrect_of_blstMatchesSpec hg1⟩

private theorem g2Affine_eq_bls (p : EthCryptographySpecs.Bls.G2) :
    g2Affine p = DecompressG2.toBlstP2Affine (G2Spec.blstLimbs p) := by
  simp only [g2Affine, fp2Encode, DecompressG2.toBlstP2Affine, G2Spec.blstLimbs,
    DecompressG2.blstPoint, DecompressG2.toBlstFp2, toArray, fpEncode_eq_bls,
    Fp2.re_toField, Fp2.im_toField]
  rfl

theorem specG2Verdict_eq_bls (b : Array U8 96#usize) :
    specG2Verdict b = UncompressG2.specVerdict b := by
  unfold specG2Verdict UncompressG2.specVerdict G2Spec.verdict
  have hb : DecompressG2.toBytes (ofArray ofU8 b) = arrayBytes b := rfl
  rw [hb]
  cases EthCryptographySpecs.Bls.G2.uncompress (arrayBytes b) with
  | error e => rfl
  | ok p =>
    cases hs : p.inSubgroup <;> simp [Except.toOption, hs, g2Affine_eq_bls]

theorem g2_decode_of_blstMatchesSpec [e : KzgExternals]
    (hg2 : UncompressG2.BlstMatchesSpec) :
    ∀ b, b = trusted_setup.G2_MONOMIAL_0 ∨ b = trusted_setup.G2_MONOMIAL_64 →
      ok (e.uncompressG2 b) = ok (specG2Verdict b) := by
  intro b _
  exact congrArg ok ((hg2 b).trans (specG2Verdict_eq_bls b).symm)

end LeanBlsSimd.Kzg
