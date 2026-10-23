import LeanBlsSimd.Kzg.FpEncoding
import LeanBlsSimd.Portable.G1DecoderContract
import LeanBlsSimd.Refines.UncompressG1
import LeanBlsSimd.Refines.UncompressG2

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

set_option exponentiation.threshold 512
set_option maxRecDepth 2048


private theorem g1Affine_eq_bls (p : EthLib.Cryptography.Bls.G1) :
    g1Affine p = DecompressG1.toBlstP1Affine (G1Spec.blstLimbs p) := by
  simp [g1Affine, DecompressG1.toBlstP1Affine, G1Spec.blstLimbs, fpEncode_eq_bls]

theorem specVerdict_eq_bls (b : Array U8 48#usize) :
    specVerdict b = UncompressG1.specVerdict b := by
  unfold specVerdict specPoint UncompressG1.specVerdict G1Spec.verdict
  change ((EthLib.Cryptography.Kzg.bytesToKzgProof (arrayBytes b)).toOption.bind
    (fun validated => (EthLib.Cryptography.Bls.G1.uncompress validated).toOption)).map _ = _
  have hb : G1Spec.toBytes (ofArray ofU8 b) = arrayBytes b := rfl
  rw [hb]
  cases EthLib.Cryptography.Kzg.bytesToKzgProof (arrayBytes b) with
  | error e => rfl
  | ok validated =>
    dsimp only [Except.toOption, Option.bind]
    cases EthLib.Cryptography.Bls.G1.uncompress validated with
    | error e => rfl
    | ok p => exact congrArg some (g1Affine_eq_bls p)

theorem g1_decode_refinement [RuntimeFeatures] (h : LeanBlsSimd.G1DecoderCorrect)
    (inputs : Slice (Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g1 inputs out = ok result ∧
      result.val = inputs.val.map specVerdict := by
  have hv : specVerdict = UncompressG1.specVerdict := funext specVerdict_eq_bls
  simpa only [hv] using UncompressG1.uncompress_in_g1_eq_spec_list h inputs out hlen

private theorem g2Affine_eq_bls (p : EthLib.Cryptography.Bls.G2) :
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
  cases EthLib.Cryptography.Bls.G2.uncompress (arrayBytes b) with
  | error e => rfl
  | ok p =>
    cases hs : p.inSubgroup <;> simp [Except.toOption, hs, g2Affine_eq_bls]

theorem g2_decode_of_blstMatchesSpec [e : BlsExternals]
    (hg2 : UncompressG2.BlstMatchesSpec) (b : Array U8 96#usize) :
    ok (e.uncompressG2 b) = ok (specG2Verdict b) := by
  exact congrArg ok ((hg2 b).trans (specG2Verdict_eq_bls b).symm)

end LeanBlsSimd.Kzg
