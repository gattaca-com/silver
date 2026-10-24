import LeanBlsSimd.Portable.Decode.Fields
import LeanBlsSimd.Portable.Decode.Spec

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Decode
open DecompressG1
set_option maxRecDepth 4096
set_option exponentiation.threshold 4096

private def scalarCore [RuntimeFeatures] (w : Array U64 6#usize) (larger : Bool) : Result (Option blst.blst_p1_affine) := do
  let x ← portable.fp.Fp.from_plain w
  let f ← portable.fp.Fp.square x
  let f1 ← portable.fp.Fp.mul f x
  let f2 ← portable.fp.Fp.add f1 portable.constants.FOUR
  let o1 ← portable.fp.Fp.sqrt f2
  let cf ← core.option.Option.Insts.CoreOpsTry_traitTryTOptionInfallible.branch o1
  match cf with
  | core.ops.control_flow.ControlFlow.Continue val => do
    let y ← portable.decompress.signed val larger
    let z ← portable.fp.Fp.is_zero y
    if z then ok none else do
      let m ← portable.g1.G1.in_g1 x y
      if m then do let p ← portable.decompress.point x y; ok (some p)
      else ok none
  | core.ops.control_flow.ControlFlow.Break residual =>
    core.option.Option.Insts.CoreOpsTry_traitFromResidualOptionInfallible.from_residual blst.blst_p1_affine residual

private theorem scalar_some [RuntimeFeatures] (bytes : Array U8 48#usize)
    (w : Array U64 6#usize) (larger : Bool)
    (ho : portable.decompress.ordinary bytes = ok (some (w,larger))) :
    portable.decompress.uncompress_in_g1 bytes = scalarCore w larger := by
  rw [portable.decompress.uncompress_in_g1,ho]
  rfl

private theorem scalarCore_fields [RuntimeFeatures] (w : Array U64 6#usize)
    (x : ZMod Bls.Fp.modulus) (larger : Bool)
    (hw : portable.fp.Fp.from_plain w = ok (Kzg.fpEncode x).l) :
    scalarCore w larger =
    if Kernel.sqrtCandidate (x^2*x+4)^2 = x^2*x+4 then do
      let y ← portable.decompress.signed (Kzg.fpEncode (Kernel.sqrtCandidate (x^2*x+4))).l larger
      let z ← portable.fp.Fp.is_zero y
      if z then ok none else do
        let m ← portable.g1.G1.in_g1 (Kzg.fpEncode x).l y
        if m then do let p ← portable.decompress.point (Kzg.fpEncode x).l y; ok (some p)
        else ok none
    else ok none := by
  simp only [scalarCore,hw,bind_tc_ok,square_encoded,mul_encoded,add_four_encoded,←sq,Fp.sqrt_refines]
  split_ifs <;> simp only [core.option.Option.Insts.CoreOpsTry_traitTryTOptionInfallible.branch,
    core.option.Option.Insts.CoreOpsTry_traitFromResidualOptionInfallible.from_residual,bind_tc_ok]

theorem scalar_refines [RuntimeFeatures] (b : Encoding) :
    portable.decompress.uncompress_in_g1 (toArray toU8 b) =
      ok ((G1Spec.verdict b).map toBlstP1Affine) := by
  by_cases ho : Ordinary b
  · rw [scalar_some _ _ _ (by rw [ordinary_refines,ordinary_some ho])]
    rw [scalarCore_fields _ (laneX b) _ (from_words ho.1 ho.2.1)]
    rw [show Kernel.sqrtCandidate (laneX b ^ 2 * laneX b + 4) = laneRoot b from rfl]
    rw [G1Spec.verdict_eq_decode,uncompress_decoded ho.1 ho.2.1]
    by_cases hr : laneRoot b ^ 2 = laneX b ^ 2 * laneX b + 4
    · simp only [hr,if_true,
        bind_tc_ok,
        signed_root,Fp.is_zero_encoded]
      have hp := lanePoint_valid hr
      by_cases hy : Bls.Fp.isZero (laneY b) = true
      · rw [if_pos hy]
        simp only [y_zero_rejected b hp hy,Bool.false_eq_true,if_false,Option.map_none]
      · rw [if_neg hy,G1.in_g1_encoded _ _ hp]
        simp only [bind_tc_ok,point_lane]
        cases hm : Bls.G1.inSubgroup (lanePoint b) <;> simp only [lanePoint] at hm <;> simp only [hm,if_true,Bool.false_eq_true,
          if_false,Option.map_some,Option.map_none]
    · simp only [hr,if_false,Option.map_none]
  · rw [portable.decompress.uncompress_in_g1,ordinary_refines,ordinary_eq,if_neg ho]
    simp only [bind_tc_ok,extraordinary_refines,nonordinary_verdict ho]
    split_ifs <;> rfl

end LeanBlsSimd.Portable.Decode
