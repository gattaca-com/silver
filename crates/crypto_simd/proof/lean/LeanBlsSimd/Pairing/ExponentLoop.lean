import LeanBlsSimd.Pairing.FinalInvariant
import LeanBlsSimd.Refines.G1x8

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Pairing.FinalExponent

set_option maxRecDepth 4000

def powerStep (a f : Bls.Fp12) (bit : Nat) : Bls.Fp12 :=
  if G1x8.is_lower_z_bit bit then f.square * a else f.square

def powerLoop (a : Bls.Fp12) (f : Bls.Fp12) : Nat → Bls.Fp12
  | 0 => f
  | n + 1 => powerLoop a (powerStep a f n) n

def scalarStep (k bit : Nat) : Nat :=
  if G1x8.is_lower_z_bit bit then k * 2 + 1 else k * 2

def scalarLoop (k : Nat) : Nat → Nat
  | 0 => k
  | n + 1 => scalarLoop (scalarStep k n) n

theorem scalar_loop_certificate : scalarLoop 1 63 = blsX := by decide +kernel

theorem power_step_good {a f : Bls.Fp12} (ha : Good a) (hf : Good f) (bit : Nat) :
    Good (powerStep a f bit) := by
  unfold powerStep
  split
  · exact hf.square.mul ha
  · exact hf.square

theorem power_loop_field (a f : Bls.Fp12) (k n : Nat)
    (hf : Fp12.toField f = Fp12.toField a ^ k) :
    Fp12.toField (powerLoop a f n) = Fp12.toField a ^ scalarLoop k n := by
  induction n generalizing f k with
  | zero => exact hf
  | succ n ih =>
    apply ih
    simp only [powerStep, scalarStep]
    split
    · rw [map_mul, Fp12.toField_square, hf, ← pow_mul, pow_succ]
    · rw [Fp12.toField_square, hf, ← pow_mul]

theorem power_loop_eq (a : Bls.Fp12) : powerLoop a a 63 = Bls.Fp12.powNat a blsX := by
  apply Fp12.toField.injective
  rw [power_loop_field a a 1 63 (by rw [pow_one]), scalar_loop_certificate, Fp12.toField_powNat]

theorem power_loop_refines {Raw : Type}
    (body : Raw × U32 → Result (ControlFlow (Raw × U32) Raw))
    (rep : Raw → Bls.Fp12 → Prop) (a : Bls.Fp12) (ha : Good a)
    (hdone : ∀ x bit, bit.val = 0 → body (x, bit) = ok (done x))
    (hstep : ∀ (n : Fin 63) x f bit, rep x f → Good f → bit.val = n.val + 1 →
      ∃ out bit', body (x, bit) = ok (cont (out, bit')) ∧ bit'.val = n.val ∧
        rep out (powerStep a f n.val))
    (n : Nat) (hn : n ≤ 63) (x : Raw) (f : Bls.Fp12) (bit : U32)
    (hx : rep x f) (hf : Good f) (hb : bit.val = n) :
    ∃ out, loop body (x, bit) = ok out ∧ rep out (powerLoop a f n) := by
  induction n generalizing x f bit with
  | zero => exact ⟨x, by rw [loop.eq_1, hdone x bit hb], hx⟩
  | succ n ih =>
    obtain ⟨out, bit', hbody, hb', hout⟩ := hstep ⟨n, by omega⟩ x f bit hx hf hb
    obtain ⟨last, hlast, rlast⟩ := ih (by omega) out (powerStep a f n) bit' hout
      (power_step_good ha hf n) hb'
    exact ⟨last, by rw [loop.eq_1, hbody]; exact hlast, rlast⟩

end LeanBlsSimd.Pairing.FinalExponent
