import LeanBlsSimd.LaneTower.InverseNorm

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.LaneTower

def inverseNormLanes (a : P F) : P F := productValues a (conjugateValues a)
def inverseValues (a : P F) : P F :=
  let n := inverseNormLanes a
  let t := inverseAdjugate n
  let d := inverseDeterminant n t
  productValues (conjugateValues a) (inverseEmbed t d)

noncomputable def inverseRun (x : fp2x8.Fp2x8) : Result fp2x8.Fp2x8 := do
  let c ← fp12.Fp12.conjugate x
  let n ← fp12.Fp12.mul x c
  let t ← adjugateRun n
  let d ← determinantRun n t
  let ni ← inverseEmbedRun t d
  fp12.Fp12.mul c ni

theorem inverse_schedule (x : fp2x8.Fp2x8) : fp12.Fp12.inverse x = inverseRun x := by
  have h6 := Fp8.multiple_of_p_refines 6#u64 (by decide)
  simp only [fp12.Fp12.inverse, inverseRun, adjugateRun, determinantRun,
    inverseEmbedRun, determinantInverseRun, invLeft, invRight, invSub, invDet,
    invComponents, invSwap, invEmbed, h6, bind_assoc, bind_tc_ok]

theorem inverse_raw_tower {x : fp2x8.Fp2x8} {a : P F} (hx : Strict2 256 x a) :
    ∃ out, fp12.Fp12.inverse x = ok out ∧
      Normal2 (fun _ => 108, fun _ => 108) out (inverseValues a) := by
  obtain ⟨c, hc, rc⟩ := conjugate_raw hx
  obtain ⟨n, hn, rn⟩ := mul_raw hx.normal rc.normal
  have rn' : Normal2 (fun _ => 256, fun _ => 256) n (inverseNormLanes a) :=
    rn.mono (by intro l; norm_num)
  obtain ⟨t, ht, rt⟩ := adjugate_raw rn'
  obtain ⟨d, hd, rd⟩ := determinant_raw rn' rt
  obtain ⟨ni, hni, rni⟩ := inverse_embed_raw rt rd
  have rni' : Normal2 (fun _ => 256, fun _ => 256) ni
      (inverseEmbed (inverseAdjugate (inverseNormLanes a))
        (inverseDeterminant (inverseNormLanes a) (inverseAdjugate (inverseNormLanes a)))) :=
    rni.mono (by intro l; norm_num)
  obtain ⟨out, hout, rout⟩ := mul_raw rc.normal rni'
  refine ⟨out, ?_, rout⟩
  simp only [inverse_schedule, inverseRun, hc, hn, ht, hd, hni, hout, bind_tc_ok]

end LeanBlsSimd.LaneTower
