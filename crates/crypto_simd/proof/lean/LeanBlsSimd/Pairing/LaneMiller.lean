import LeanBlsSimd.Pairing.MillerLoop
import LeanBlsSimd.Pairing.LaneMillerStep
import LeanBlsSimd.Pairing.LaneFactors

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.Pairing.LaneLines

open LaneTower

set_option maxRecDepth 2000

theorem miller_loop_refines (factors z : fp8.Fp8) (v : Factors) (hv : FactorsRep factors z v)
    (present : U8) (n : Nat) (hn : n ≤ 63) (x : fp2x8.Fp2x8) (f : Bls.Fp12)
    (hx : Rep x f) (step : Usize) (bit : U32)
    (hs : step.val = consumed n) (hb : bit.val = n) (hfirst : n = 63 → f = Bls.Fp12.one) :
    ∃ out, pairing.MillerLines.miller_loop_loop kzg.pairing_lines.PAIRING_LINES
      present factors z x step bit = ok out ∧
      Rep out (remainingMiller v (maskPresence present) n f) := by
  let body := fun (state : fp2x8.Fp2x8 × Usize × U32) =>
    pairing.MillerLines.miller_loop_loop.body kzg.pairing_lines.PAIRING_LINES
      present factors z state.1 state.2.1 state.2.2
  have hdone : ∀ x step bit, bit.val = 0 → body (x, step, bit) = ok (done x) := by
    intro x step bit hb
    simp only [body, pairing.MillerLines.miller_loop_loop.body,
      UScalar.lt_equiv, hb, Nat.not_lt_zero, if_false]
  exact loop_refines body Rep v (maskPresence present) hdone
    (fun n x f step bit hx hs hb hfirst => miller_body factors z v hv present n x f hx step bit hs hb hfirst)
    n hn x f step bit hx hs hb hfirst

theorem miller_refines (raw : g1x8.G1x8) (points : Fin 8 → Bls.G1) (hp : PointsRep raw points) :
    ∃ out, pairing.MillerLines.miller_loop kzg.pairing_lines.PAIRING_LINES raw = ok out ∧
      Rep out (combinedMiller (firstPoints points)).conjugate := by
  obtain ⟨factors, z, hprep, hv⟩ := factors_refines raw points hp
  obtain ⟨one, hone, rone⟩ := one_refines
  let present := ~~~ toU8 (ofFp8 raw.z).is_zero_mask
  have hpres : maskPresence present = presence (firstPoints points) := presence_refines raw points hp
  obtain ⟨f, hloop, rf⟩ := miller_loop_refines factors z (g1Factors (firstPoints points)) hv
    present 63 (by omega) one Bls.Fp12.one rone 0#usize 63#u32
    (by rw [consumed_start]; rfl) rfl (fun _ => rfl)
  rw [hpres, remaining_miller_start] at rf
  obtain ⟨out, hout, rout⟩ := conjugate_refines rf
  have hbit : Array.index_usize constants.Z_BITS 0#usize = ok 63#u32 := by
    rw [Z_BITS_index 0#usize (by decide)]
    rfl
  refine ⟨out, ?_, rout⟩
  simp only [pairing.MillerLines.miller_loop, Fp8.is_zero_mask_refines, lift, bind_tc_ok]
  have hxz := Fp8.mul_refines raw.x raw.z
  have hfac := Fp8.permute2_refines (toFp8 ((ofFp8 raw.x).mul (ofFp8 raw.z))) raw.y factorIndices
  have hzz := Fp8.square_refines raw.z
  have hz := Fp8.mul_refines (toFp8 (ofFp8 raw.z).square) raw.z
  simp only [hxz, hfac, hzz, hz, bind_tc_ok] at hprep
  have he := Result.ok.inj hprep
  obtain ⟨hfac', hz'⟩ := Prod.mk.inj he
  dsimp only [factorIndices] at hfac hfac'
  dsimp only [present] at hloop
  simp only [hxz, hfac, hzz, hz, bind_tc_ok, hfac', hz', hone, hbit, hloop, hout]

end LeanBlsSimd.Pairing.LaneLines
