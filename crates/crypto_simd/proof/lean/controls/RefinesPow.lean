import controls.G1Fallback
import LeanBlsSimd.Refines.DecompressG2
import LeanBlsSimd.Refines.G2x8
import LeanBlsSimd.Proofs.Convert
import LeanBlsSimd.Refines.G1Wrapper

/-! Mutation controls for `LeanBlsSimd/Refines/`. Each `fail_if_success` checks that a proof script
rejects a mutation; each plain `example` must pass.

Each mutated definition takes the changed part as a parameter. An `rfl` check identifies its
unmutated instance with the original, and the same proof script succeeds on that instance.
Separate concrete examples refute the mutated claims where described below. -/

namespace LeanBlsSimd

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls

-- A mutated proof stops at its first failing step, so the linters flag the steps after it.
set_option linter.unreachableTactic false
set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false

/-! ## `Fp8::pow_p_minus_3_over_4`: the start of the window loop

The window loop counts down from 94, after window 94 has picked the starting entry. A generated
`pow_p_minus_3_over_4` that counts down from 95 reads window 94 twice, and must not refine the
model's. The same script proves that this mutant refines a model folding over `List.range 95`.
That model raises a lane to the power (p − 3)/4 + 3 · 2^381, and on a lane holding 2 the two
powers differ. So the mutated claim is false, not only unproved. -/

section Pow

open EthLib.Cryptography.Bls

def powWith (start : Usize) (self : fp8.Fp8) : Result fp8.Fp8 := do
  let f ← fp8.Fp8.one
  let table := Array.repeat 16#usize f
  let a ← Array.update table 1#usize self
  let table1 ← fp8.Fp8.pow_p_minus_3_over_4_loop0 { start := 2#usize, «end» := 16#usize } self a
  let i ← Array.index_usize constants.P_MINUS_3_OVER_4_WINDOWS 94#usize
  let i1 ← lift (UScalar.cast .Usize i)
  let r ← Array.index_usize table1 i1
  fp8.Fp8.pow_p_minus_3_over_4_loop1 table1 r start

example : powWith 94#usize = fp8.Fp8.pow_p_minus_3_over_4 := rfl

def Fp8.powWith (n : ℕ) (self : Fp8) : Fp8 :=
  let table : Vector Fp8 16 := .replicate 16 one
  let table := table.set 1 self
  let table := ((List.finRange 16).drop 2).foldl (init := table) fun table (k : Fin 16) =>
    table.set k (table[k.val - 1].mul self)
  let r := table[P_MINUS_3_OVER_4_WINDOWS[94]!]!
  (List.range n).reverse.foldl (windowStep table) r

example : Fp8.powWith 94 = Fp8.pow_p_minus_3_over_4 := rfl

set_option hygiene false in
/-- The proof of `Fp8.pow_p_minus_3_over_4_refines`, over `powWith`, and over `Fp8.powWith` where
the claim names it. -/
local macro "pow_proof" : tactic => `(tactic| (
  intro self
  unfold powWith
  simp only [Fp8.one_refines, bind_tc_ok]
  rw [← toArray_replicate toFp8 Fp8.one (show (16#usize).val = 16 from rfl),
    update_eq _ _ _ (by decide),
    toArray_set_of_eq toFp8 _ _ 1#usize 1 (by decide) (ofFp8 self) self rfl (by simp)]
  simp only [bind_tc_ok, Fp8.pow_table_refines]
  have h94 : P_MINUS_3_OVER_4_WINDOWS[94]! < 16 := windows_lt 94 (by simp)
  simp only [bind_tc_ok, P_MINUS_3_OVER_4_WINDOWS_index 94#usize (by decide), lift,
    cast_Usize_ofNatCore]
  rw [index_usize_toArray _ _ _ _ (by rw [UScalar.ofNatCore_val_eq]; exact h94)]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  rw [Fp8.pow_windows_refines _ _ _ _ rfl (by decide),
    ← getElem!_pos _ P_MINUS_3_OVER_4_WINDOWS[94]! h94]
  simp only [Fp8.pow_p_minus_3_over_4, Fp8.powWith, UScalar.ofNatCore_val_eq]))

example : ∀ self : fp8.Fp8,
    powWith 94#usize self = ok (toFp8 (ofFp8 self).pow_p_minus_3_over_4) := by
  pow_proof

example : True := by
  fail_if_success
    have : ∀ self : fp8.Fp8,
        powWith 95#usize self = ok (toFp8 (ofFp8 self).pow_p_minus_3_over_4) := by
      pow_proof
  trivial

theorem powWith_95_refines : ∀ self : fp8.Fp8,
    powWith 95#usize self = ok (toFp8 (Fp8.powWith 95 (ofFp8 self))) := by
  pow_proof

/-- The exponent of `Fp8.powWith 95`: window 94 enters twice. -/
theorem windows_horner_95 :
    (List.range 95).reverse.foldl (fun e w => 16 * e + P_MINUS_3_OVER_4_WINDOWS[w]!)
      P_MINUS_3_OVER_4_WINDOWS[94]! = (Fp.modulus - 3) / 4 + 3 * 2 ^ 381 := by
  decide +kernel

theorem lane_powWith_95 {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) :
    decode ((Fp8.powWith 95 x).lane l) =
      decode (x.lane l) ^ ((Fp.modulus - 3) / 4 + 3 * 2 ^ 381) := by
  have ht := Fp8.table_fold hx ((List.finRange 16).drop 2) 1 _ le_rfl rfl (Fp8.part_table_init hx)
  unfold Fp8.powWith
  dsimp only
  generalize ((List.finRange 16).drop 2).foldl _ _ = table at ht ⊢
  have h94 : P_MINUS_3_OVER_4_WINDOWS[94]! < 16 := by decide
  have ht94 := ht ⟨_, h94⟩
  simp only [Fin.getElem_fin] at ht94
  rw [← getElem!_pos table _ h94] at ht94
  have := Fp8.window_fold ht ((List.range 95).reverse) _ _
    (fun w hw => windows_lt w (by simpa using hw)) ht94.1 ht94.2
  rw [windows_horner_95] at this
  exact this.2

/-- `x ^ 2 ^ k % m`, by `k` squarings, so that the kernel can evaluate it for `k = 381`. -/
def sqIter (m : ℕ) : ℕ → ℕ → ℕ
  | 0, x => x
  | k + 1, x => sqIter m k (x * x % m)

theorem sqIter_eq (m k x : ℕ) : ((sqIter m k x : ℕ) : ZMod m) = (x : ZMod m) ^ 2 ^ k := by
  induction k generalizing x with
  | zero => simp [sqIter]
  | succ k ih =>
    rw [sqIter, ih, ZMod.natCast_mod, Nat.cast_mul, pow_succ, pow_mul, sq, mul_pow]

theorem two_pow_ne_one : ((2 : ℕ) : ZMod Fp.modulus) ^ (3 * 2 ^ 381) ≠ 1 := by
  rw [pow_mul, show ((2 : ℕ) : ZMod Fp.modulus) ^ 3 = ((8 : ℕ) : ZMod Fp.modulus) by norm_num,
    ← sqIter_eq]
  intro h
  have := congrArg ZMod.val h
  rw [ZMod.val_natCast, ZMod.val_one] at this
  revert this
  decide +kernel

example : ¬ ∀ self : fp8.Fp8,
    powWith 95#usize self = ok (toFp8 (ofFp8 self).pow_p_minus_3_over_4) := by
  intro h
  let v : Vector Limbs 8 := .replicate 8 (.ofList [2])
  have hv : Fp8Inv v[(0 : Fin 8)] := ⟨by decide, by decide +kernel⟩
  have hval : val v[(0 : Fin 8)] = 2 := by decide +kernel
  obtain ⟨hx, hdx⟩ := Fp8.lane_from_plain (l := 0) hv
  have e := congrArg ofFp8 (Result.ok.inj
    ((powWith_95_refines (toFp8 (Fp8.from_plain v))).symm.trans (h (toFp8 (Fp8.from_plain v)))))
  simp only [ofFp8_toFp8] at e
  have h1 := lane_powWith_95 hx
  rw [e, (Fp8.lane_pow_p_minus_3_over_4 hx).2, hdx, hval, pow_add] at h1
  have h2 : ((2 : ℕ) : ZMod Fp.modulus) ^ ((Fp.modulus - 3) / 4) ≠ 0 := by
    apply pow_ne_zero
    rw [Ne, ZMod.natCast_eq_zero_iff]
    decide +kernel
  exact two_pow_ne_one ((mul_eq_left₀ h2).mp h1.symm)

end Pow

end LeanBlsSimd
