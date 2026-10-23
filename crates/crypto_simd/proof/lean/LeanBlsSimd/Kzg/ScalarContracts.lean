import LeanBlsSimd.Kzg.Representation
import LeanBlsSimd.Kzg.RepresentationLemmas
import LeanBlsSimd.Extracted.Funs

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg

/-- Arithmetic laws for the generated Montgomery scalar implementation. -/
structure FrCorrect : Prop where
  fr_add : ∀ x y, fr.fr_add (frEncode x) (frEncode y) = ok (frEncode (x + y))
  fr_sub : ∀ x y, fr.fr_sub (frEncode x) (frEncode y) = ok (frEncode (x - y))
  fr_mul : ∀ x y, fr.fr_mul (frEncode x) (frEncode y) = ok (frEncode (x * y))

/-- Canonical decoding, reducing decoding and serialization of generated scalars. -/
structure FrBytesCorrect : Prop where
  fr_bytes : ∀ b, fr.fr_from_bytes b =
    ok ((Kzg.bytesToBlsField (arrayBytes b)).toOption.map frEncode)
  fr_reduced : ∀ b, fr.fr_from_bytes_reduced b =
    ok (frEncode (Fr.ofNat (Fr.bytesBEToNat (arrayBytes b))))
  fr_to_bytes : ∀ x, ∃ result, fr.fr_to_bytes (frEncode x) = ok result ∧
    arrayBytes result = Kzg.blsFieldToBytes x
  fr_to_words : ∀ x, fr.fr_to_words (frEncode x) = ok (words 4#usize x.val)

end LeanBlsSimd.Kzg
