import LeanBlsSimd.Portable.Decode.Ordinary
import LeanBlsSimd.Portable.G1.Exclusions
import LeanBlsSimd.Portable.Fp.Sign
import LeanBlsSimd.Kzg.FpEncoding

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Decode
open DecompressG1
set_option maxRecDepth 4096
set_option exponentiation.threshold 4096

theorem words_bound {b : Encoding} (hu : (decodeLane b).undecided = false)
    (hv : (decodeLane b).invalid = false) : Word64.value (words b) < Bls.Fp.modulus := by
  rw [words_value]
  exact_mod_cast (decodeLane_ok hu hv).choose_spec.choose_spec.choose

theorem words_field {b : Encoding} (hu : (decodeLane b).undecided = false)
    (hv : (decodeLane b).invalid = false) : Bls.Fp.ofNat (Kzg.limbs (words b).val) = laneX b := by
  obtain ⟨hc,hi,hp,hd⟩ := decodeLane_ok hu hv
  rw [←Kzg.val64_eq_limbs,ofArray_toArray_ofU64,val64_fp_words,laneX,hd]
  rfl

theorem from_words [RuntimeFeatures] {b : Encoding} (hu : (decodeLane b).undecided = false)
    (hv : (decodeLane b).invalid = false) :
    portable.fp.Fp.from_plain (words b) = ok (Kzg.fpEncode (laneX b)).l := by
  rw [Fp.from_plain_refines _ (words_bound hu hv),words_field hu hv]

theorem four_encoded : portable.constants.FOUR = (Kzg.fpEncode (4 : ZMod Bls.Fp.modulus)).l := by
  unfold portable.constants.FOUR
  rfl

theorem square_encoded [RuntimeFeatures] (x : ZMod Bls.Fp.modulus) :
    portable.fp.Fp.square (Kzg.fpEncode x).l = ok (Kzg.fpEncode (x*x)).l :=
  Fp.square_encoded x

theorem mul_encoded [RuntimeFeatures] (x y : ZMod Bls.Fp.modulus) :
    portable.fp.Fp.mul (Kzg.fpEncode x).l (Kzg.fpEncode y).l = ok (Kzg.fpEncode (x*y)).l :=
  Fp.mul_encoded x y

theorem add_four_encoded (x : ZMod Bls.Fp.modulus) :
    portable.fp.Fp.add (Kzg.fpEncode x).l portable.constants.FOUR = ok (Kzg.fpEncode (x+(4 : ZMod Bls.Fp.modulus))).l := by
  rw [four_encoded]
  exact Fp.add_encoded x 4

theorem signed_encoded [RuntimeFeatures] (x : ZMod Bls.Fp.modulus) (larger : Bool) :
    portable.decompress.signed (Kzg.fpEncode x).l larger =
      ok (Kzg.fpEncode (if Kernel.isLargerRootFp x ^^ larger then -x else x)).l := by
  rw [Fp.signed_refines,Kernel.isLargerRootFp_eq]
  cases hs : Bls.Fp.signBit x <;> cases larger <;> rfl

theorem signed_root [RuntimeFeatures] (b : Encoding) :
    portable.decompress.signed (Kzg.fpEncode (laneRoot b)).l (decodeLane b).largerRoot =
      ok (Kzg.fpEncode (laneY b)).l :=
  signed_encoded (laneRoot b) (decodeLane b).largerRoot

theorem point_encoded (x y : ZMod Bls.Fp.modulus) :
    portable.decompress.point (Kzg.fpEncode x).l (Kzg.fpEncode y).l =
      ok (toBlstP1Affine ⟨DecompressG2.blstFp x,DecompressG2.blstFp y⟩) := by
  rw [Kzg.fpEncode_eq_bls,Kzg.fpEncode_eq_bls]
  rfl

theorem point_lane (b : Encoding) :
    portable.decompress.point (Kzg.fpEncode (laneX b)).l (Kzg.fpEncode (laneY b)).l =
      ok (toBlstP1Affine (G1Spec.blstLimbs (lanePoint b))) := by
  rw [point_encoded,blstLimbs_lanePoint]

theorem y_zero_rejected (b : Encoding) (hp : Bls.G1.Valid (lanePoint b))
    (hy : Bls.Fp.isZero (laneY b) = true) : Bls.G1.inSubgroup (lanePoint b) = false := by
  have he : laneY b = 0 := by
    apply Fin.ext
    simpa only [Bls.Fp.isZero,beq_iff_eq] using hy
  simpa only [lanePoint,he] using G1.y_zero_not_in_subgroup (laneX b) (by simpa only [lanePoint,he] using hp)

end LeanBlsSimd.Portable.Decode
