import LeanBlsSimd.Pairing.MillerSchedule

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Pairing

noncomputable section

theorem loop_refines {Raw : Type}
    (body : Raw × Usize × U32 → Result (ControlFlow (Raw × Usize × U32) Raw))
    (rep : Raw → Fp12 → Prop) (v : Factors) (present : Array Bool 2#usize)
    (hdone : ∀ x step bit, bit.val = 0 → body (x, step, bit) = ok (done x))
    (hstep : ∀ (n : Fin 63) x f step bit, rep x f →
      step.val = consumed (n.val + 1) → bit.val = n.val + 1 →
      (n.val + 1 = 63 → f = Fp12.one) →
      ∃ x' step' bit', body (x, step, bit) = ok (cont (x', step', bit')) ∧
        step'.val = consumed n.val ∧ bit'.val = n.val ∧ rep x' (bitStep v present n f))
    (n : Nat) (hn : n ≤ 63) (x : Raw) (f : Fp12) (step : Usize) (bit : U32)
    (hx : rep x f) (hs : step.val = consumed n) (hb : bit.val = n)
    (hfirst : n = 63 → f = Fp12.one) :
    ∃ out, loop body (x, step, bit) = ok out ∧ rep out (remainingMiller v present n f) := by
  induction n generalizing x f step bit with
  | zero =>
    refine ⟨x, ?_, ?_⟩
    · rw [loop.eq_1, hdone x step bit hb]
    · simpa only [remainingMiller, remaining_zero, List.foldl_nil] using hx
  | succ n ih =>
    obtain ⟨x', step', bit', hbody, hs', hb', hx'⟩ :=
      hstep ⟨n, by omega⟩ x f step bit hx hs hb hfirst
    obtain ⟨out, hout, hrep⟩ := ih (by omega) x' (bitStep v present ⟨n, by omega⟩ f)
      step' bit' hx' hs' hb' (by intro he; omega)
    refine ⟨out, ?_, ?_⟩
    · rw [loop.eq_1, hbody]
      exact hout
    · rw [show n + 1 = (⟨n, by omega⟩ : Fin 63).val + 1 from rfl, remaining_miller_step]
      exact hrep

end

end LeanBlsSimd.Pairing
