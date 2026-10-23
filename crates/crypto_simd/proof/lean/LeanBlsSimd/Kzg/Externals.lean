import LeanBlsSimd.Kzg.Representation
import LeanBlsSimd.Kzg.RepresentationLemmas
import LeanBlsSimd.Extracted.Funs

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

def G1DecoderCorrect (e : KzgExternals) : Prop :=
  ∀ (inputs : Slice (Aeneas.Std.Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine)),
    out.val.length = inputs.val.length →
    ∃ result, @silver_crypto_simd.bls.uncompress_in_g1 e.toBlsExternals inputs out = ok result ∧
      result.val = inputs.val.map specVerdict

structure BlstCorrect (e : KzgExternals) : Prop where
  g2_decode : ∀ b,
    b = trusted_setup.G2_MONOMIAL_0 ∨ b = trusted_setup.G2_MONOMIAL_64 →
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
  lincomb : ∀ ps fs scratch,
    ps.val.length = fs.val.length →
    (∀ p ∈ ps.val, G1AffineValid p) → (∀ f ∈ fs.val, FrReduced f) →
    ∃ result scratch', e.g1Lincomb ps fs scratch = ok (result, scratch') ∧
      G1Rep result (G1.msm (ps.val.map g1ReadAffine).toArray (fs.val.map frRead).toArray)
  pairing : ∀ p q p' q',
    G1AffineValid p → G2AffineValid q → G1AffineValid p' → G2AffineValid q' →
    e.pairingCheck p q p' q' =
      ok (Bls.pairingCheck #[(g1ReadAffine p, g2ReadAffine q),
        (g1ReadAffine p', g2ReadAffine q')])

def FrToBytesCorrect (e : KzgExternals) : Prop :=
  ∀ x, ∃ result, e.frToBytes (frEncode x) = ok result ∧
    arrayBytes result = Kzg.blsFieldToBytes x

structure ExternalsCorrect (e : KzgExternals) : Prop where
  blst : BlstCorrect e
  g1 : G1DecoderCorrect e

end LeanBlsSimd.Kzg
