import LeanBlsSimd.Pairing.MillerLoop
import LeanBlsSimd.Pairing.PortableMillerStep
import LeanBlsSimd.Pairing.PortableFactors

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls
open silver_crypto_simd

namespace LeanBlsSimd.Pairing.PortableLines

set_option maxRecDepth 2000
set_option exponentiation.threshold 4096

theorem miller_loop_encoded [RuntimeFeatures] (lines : portable.pairing.PairingLines)
    (hl : Kzg.PortableLinesRep lines)
    (factors : Array (Array portable.fp.Fp 3#usize) 2#usize) (v : Factors)
    (hf : FactorsRep factors v) (present : Array Bool 2#usize)
    (n : Nat) (hn : n ≤ 63) (f : Fp12) (step : Usize) (bit : U32)
    (hs : step.val = consumed n) (hb : bit.val = n) (hfirst : n = 63 → f = Fp12.one) :
    portable.pairing.PairingLines.miller_loop_loop1 lines factors present
      (Portable.Fp12.encode f) step bit = ok (Portable.Fp12.encode (remainingMiller v present n f)) := by
  let body := fun (state : portable.fp12.Fp12 × Usize × U32) =>
    portable.pairing.PairingLines.miller_loop_loop1.body lines factors present state.1 state.2.1 state.2.2
  have hdone : ∀ x step bit, bit.val = 0 → body (x, step, bit) = ok (done x) := by
    intro x step bit hb
    simp only [body, portable.pairing.PairingLines.miller_loop_loop1.body,
      UScalar.lt_equiv, hb, Nat.not_lt_zero, if_false]
  have hstep : ∀ (n : Fin 63) x f step bit, x = Portable.Fp12.encode f →
      step.val = consumed (n.val + 1) → bit.val = n.val + 1 →
      (n.val + 1 = 63 → f = Fp12.one) →
      ∃ x' step' bit', body (x, step, bit) = ok (cont (x', step', bit')) ∧
        step'.val = consumed n.val ∧ bit'.val = n.val ∧ x' = Portable.Fp12.encode (bitStep v present n f) := by
    intro n x f step bit hx hs hb hfirst
    subst x
    obtain ⟨step', bit', hbody, hs', hb'⟩ := miller_body lines hl factors v hf present n f step bit hs hb hfirst
    exact ⟨_, step', bit', hbody, hs', hb', rfl⟩
  obtain ⟨out, hout, hrep⟩ := loop_refines body (fun x f => x = Portable.Fp12.encode f)
    v present hdone hstep n hn (Portable.Fp12.encode f) f step bit rfl hs hb hfirst
  rw [hrep] at hout
  exact hout

theorem point_infinity (p : Bls.G1) :
    portable.g1.G1.is_infinity (Portable.G1.encode p) = ok p.isInfinity := by
  simp only [portable.g1.G1.is_infinity, Portable.G1.encode, Portable.Fp.is_zero_encoded]
  rfl

theorem miller_encoded [RuntimeFeatures] (lines : portable.pairing.PairingLines)
    (hl : Kzg.PortableLinesRep lines) (raw : Array portable.g1.G1 2#usize)
    (points : Fin 2 → Bls.G1) (hp : PointsRep raw points) :
    portable.pairing.PairingLines.miller_loop lines raw =
      ok (Portable.Fp12.encode (combinedMiller points).conjugate) := by
  let scratch := Array.repeat 2#usize (Array.repeat 3#usize portable.fp.Fp.ZERO)
  obtain ⟨factors, hprep, hf⟩ := factors_refines raw points hp scratch
  dsimp only [scratch] at hprep
  have h0 : Array.index_usize raw 0#usize = ok (Portable.G1.encode (points 0)) := by
    rw [index_usize_eq raw 0#usize (by decide)]
    exact congrArg ok (hp 0)
  have h1 : Array.index_usize raw 1#usize = ok (Portable.G1.encode (points 1)) := by
    rw [index_usize_eq raw 1#usize (by decide)]
    exact congrArg ok (hp 1)
  have hbit : Array.index_usize bls.constants.Z_BITS 0#usize = ok 63#u32 := by
    rw [Z_BITS_index 0#usize (by decide)]
    rfl
  have hloop := miller_loop_encoded lines hl factors (g1Factors points) hf (presence points)
    63 (by omega) Fp12.one 0#usize 63#u32 (by rw [consumed_start]; rfl) rfl (fun _ => rfl)
  rw [remaining_miller_start] at hloop
  simp only [portable.pairing.PairingLines.miller_loop, hprep, bind_tc_ok, h0, h1,
    point_infinity, hbit, Portable.Fp12.one_encoded, decide_not, Bool.decide_coe]
  change (do
    let f ← portable.pairing.PairingLines.miller_loop_loop1 lines factors (presence points)
      (Portable.Fp12.encode Fp12.one) 0#usize 63#u32
    portable.fp12.Fp12.conjugate f) = _
  rw [hloop]
  simp only [bind_tc_ok, Portable.Fp12.conjugate_encoded]

end LeanBlsSimd.Pairing.PortableLines
