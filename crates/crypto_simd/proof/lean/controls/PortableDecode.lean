import LeanBlsSimd.Portable.Decode.Correct

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Decode.Controls
open DecompressG1
set_option maxRecDepth 4096
set_option exponentiation.threshold 4096

def finiteBytes (n : Nat) : Encoding :=
  let b : Encoding := .ofFn fun i => UInt8.ofNat (n / 256^(47-i.val))
  b.set 0 (b[0] ||| 0x80)

theorem zero_x_rejected : portable.decompress.ordinary (toArray toU8 (finiteBytes 0)) = ok none := by
  rw [ordinary_refines]
  apply congrArg ok
  decide +kernel

theorem modulus_x_rejected : portable.decompress.ordinary (toArray toU8 (finiteBytes Bls.Fp.modulus)) = ok none := by
  rw [ordinary_refines]
  apply congrArg ok
  decide +kernel

theorem canonical_x_retained :
    portable.decompress.ordinary (toArray toU8 (finiteBytes 1)) = ok (some (words (finiteBytes 1),false)) := by
  rw [ordinary_refines]
  rfl

theorem canonical_infinity_accepted [RuntimeFeatures] :
    portable.decompress.uncompress_in_g1 (toArray toU8 G1Spec.infinity) =
      ok (some (toBlstP1Affine (point (.replicate 6 0) (.replicate 6 0)))) := by
  rw [scalar_refines,G1Spec.infinity_verdict]
  rfl

theorem nonzero_infinity_tail_rejected [RuntimeFeatures] :
    portable.decompress.uncompress_in_g1 (toArray toU8 (G1Spec.infinity.set 47 1)) = ok none := by
  rw [scalar_refines,nonordinary_verdict (by decide +kernel),if_neg (by decide +kernel)]
  rfl

theorem zero_x_decoder_rejected [RuntimeFeatures] :
    portable.decompress.uncompress_in_g1 (toArray toU8 (finiteBytes 0)) = ok none := by
  rw [scalar_refines,nonordinary_verdict (by decide +kernel),if_neg (by decide +kernel)]
  rfl

theorem pair_keeps_lane_order [RuntimeFeatures] :
    portable.decompress.uncompress_pair_in_g1 (toArray toU8 G1Spec.infinity) (toArray toU8 (finiteBytes 0)) =
      ok (Array.make 2#usize [some (toBlstP1Affine (point (.replicate 6 0) (.replicate 6 0))),none] (by rfl)) := by
  rw [pair_refines,G1Spec.infinity_verdict,nonordinary_verdict (by decide +kernel),if_neg (by decide +kernel)]
  rfl

#print axioms pair_refines
#print axioms g1_decoder_correct

#print axioms G1.x_zero_order_three
#print axioms G1.x_zero_not_in_subgroup
#print axioms G1.y_zero_not_in_subgroup
#print axioms ordinary_refines
#print axioms extraordinary_refines
#print axioms scalar_refines

end LeanBlsSimd.Portable.Decode.Controls
