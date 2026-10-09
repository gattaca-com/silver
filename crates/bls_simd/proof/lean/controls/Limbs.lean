import LeanBlsSimd.Proofs.Limbs

/-! Negative controls for `LeanBlsSimd.Proofs.Limbs`. Each `fail_if_success` wraps a claim that
must fail; each plain `example` must pass.

The mutants run through `mulWith`, a copy of `Lane.mul` that takes its IFMA pair and its
reduction carry shift as parameters. The first example pins the copy to the model. Whole-product
claims are stated in `ℕ`: `val m * R ≡ val a * val b` modulo p, which is `mul_spec`'s value
equation multiplied by the unit R. -/

namespace LeanBlsSimd

open EthCryptographySpecs.Bls Lane

-- A mutated proof stops at its first failing step, so the linter flags the steps after it.
set_option linter.unreachableTactic false

def muladd_rowWith (lo hi : UInt64 → UInt64 → UInt64 → UInt64) (t : Acc) (a : Limbs)
    (b_i : UInt64) (i : Fin LIMBS) : Acc :=
  (List.finRange LIMBS).foldl (init := t) fun t (j : Fin LIMBS) =>
    let t := t.set (i.val + j.val) (lo t[i.val + j.val] a[j] b_i)
    t.set (i.val + j.val + 1) (hi t[i.val + j.val + 1] a[j] b_i)

def reduce_rowWith (lo hi : UInt64 → UInt64 → UInt64 → UInt64) (shift : ℕ) (t : Acc) (p : Limbs)
    (pinv : UInt64) (i : Fin LIMBS) : Acc :=
  let q := lo zero t[i.val] pinv
  let t := (List.finRange LIMBS).foldl (init := t) fun t (j : Fin LIMBS) =>
    let t := t.set (i.val + j.val) (lo t[i.val + j.val] q p[j])
    t.set (i.val + j.val + 1) (hi t[i.val + j.val + 1] q p[j])
  t.set (i.val + 1) (t[i.val + 1] + srli shift t[i.val])

def mulWith (lo hi : UInt64 → UInt64 → UInt64 → UInt64) (shift : ℕ) (self rhs : Limbs) :
    Limbs :=
  let p := splat_limbs (.ofList P)
  let pinv := splat (.ofNat P_INV52)
  let t : Acc := .replicate _ zero
  let t := muladd_rowWith lo hi t self rhs[0] 0
  let t := muladd_rowWith lo hi t self rhs[1] 1
  let t := muladd_rowWith lo hi t self rhs[2] 2
  let t := muladd_rowWith lo hi t self rhs[3] 3
  let t := muladd_rowWith lo hi t self rhs[4] 4
  let t := muladd_rowWith lo hi t self rhs[5] 5
  let t := muladd_rowWith lo hi t self rhs[6] 6
  let t := muladd_rowWith lo hi t self rhs[7] 7
  let t := reduce_rowWith lo hi shift t p pinv 0
  let t := reduce_rowWith lo hi shift t p pinv 1
  let t := reduce_rowWith lo hi shift t p pinv 2
  let t := reduce_rowWith lo hi shift t p pinv 3
  let t := reduce_rowWith lo hi shift t p pinv 4
  let t := reduce_rowWith lo hi shift t p pinv 5
  let t := reduce_rowWith lo hi shift t p pinv 6
  let t := reduce_rowWith lo hi shift t p pinv 7
  let mask := splat (.ofNat MASK52)
  let r : Limbs := .replicate _ zero
  let r := r.set 0 t[LIMBS]
  (List.finRange (LIMBS - 1)).foldl (init := r) fun r (j : Fin (LIMBS - 1)) =>
    let r := r.set (j.val + 1) (t[LIMBS + j.val + 1] + srli 52 r[j.val])
    r.set j.val (r[j.val] &&& mask)

example : mulWith madd52lo madd52hi 52 = Lane.mul := rfl

/-- `madd52lo` adding the product's low 64 bits instead of its low 52. -/
def madd52loFull (a b c : UInt64) : UInt64 := a + UInt64.ofNat (lo52 b * lo52 c)

/-- `madd52lo` without the truncation of its operands to 52 bits. -/
def madd52loWide (a b c : UInt64) : UInt64 := a + UInt64.ofNat (b.toNat * c.toNat % 2 ^ 52)

/-- `madd52hi` without the truncation of its operands to 52 bits. -/
def madd52hiWide (a b c : UInt64) : UInt64 := a + UInt64.ofNat (b.toNat * c.toNat / 2 ^ 52)

/-- p − 1 and 2p − 1, in normalised limbs. -/
def pMinus1 : Limbs := .ofList (limbs52 (Fp.modulus - 1))
def twoPMinus1 : Limbs := .ofList (limbs52 (2 * Fp.modulus - 1))

/-- The value 2^52 with an unnormalised limb 0. -/
def wide : Limbs := .ofList [2 ^ 52, 0, 0, 0, 0, 0, 0, 0]

example : Fp8Inv pMinus1 ∧ Fp8Inv twoPMinus1 :=
  ⟨⟨by decide, by decide +kernel⟩, ⟨by decide, by decide +kernel⟩⟩

example : val (Lane.mul pMinus1 twoPMinus1) * R % Fp.modulus =
    val pMinus1 * val twoPMinus1 % Fp.modulus := by
  decide +kernel

/-! ## The IFMA low half reduced modulo 2^52 -/

example : True := by
  fail_if_success
    have : ∀ a b c : UInt64, a.toNat + 2 ^ 52 ≤ 2 ^ 64 →
        (madd52loFull a b c).toNat = a.toNat + lo52 b * lo52 c % 2 ^ 52 := by
      intro a b c h
      have := Nat.mod_lt (lo52 b * lo52 c) (show 2 ^ 52 > 0 by norm_num)
      unfold madd52loFull
      rw [UInt64.toNat_add, UInt64.toNat_ofNat', Nat.mod_eq_of_lt (by omega),
        Nat.mod_eq_of_lt (by omega)]
  trivial

example : (madd52loFull 0 (2 ^ 52 - 1) 2).toNat ≠ 0 + lo52 (2 ^ 52 - 1) * lo52 2 % 2 ^ 52 := by
  decide

example : val (mulWith madd52loFull madd52hi 52 pMinus1 twoPMinus1) * R % Fp.modulus ≠
    val pMinus1 * val twoPMinus1 % Fp.modulus := by
  decide +kernel

/-! ## The carry shift of `reduce_row` -/

example : True := by
  fail_if_success
    have : ∀ x : UInt64, (srli 51 x).toNat = x.toNat / 2 ^ 52 := by
      intro x
      simp [srli, Nat.shiftRight_eq_div_pow]
  trivial

example : (srli 51 (2 ^ 51)).toNat ≠ (2 ^ 51 : UInt64).toNat / 2 ^ 52 := by decide

example : val (mulWith madd52lo madd52hi 51 pMinus1 twoPMinus1) * R % Fp.modulus ≠
    val pMinus1 * val twoPMinus1 % Fp.modulus := by
  decide +kernel

/-! ## `Fp8Inv.normal`, which the operand truncation makes necessary

`wide` meets `Fp8Inv.bound` but not `Fp8Inv.normal`. The model drops bit 52 of its limb 0;
without the operand truncation, the same product comes out right. -/

example : val wide < 2 * Fp.modulus ∧ ¬ (wide[0].toNat < 2 ^ LIMB_BITS) :=
  ⟨by decide +kernel, by decide⟩

example : val (Lane.mul wide twoPMinus1) * R % Fp.modulus ≠
    val wide * val twoPMinus1 % Fp.modulus := by
  decide +kernel

example : val (mulWith madd52loWide madd52hiWide 52 wide twoPMinus1) * R % Fp.modulus =
    val wide * val twoPMinus1 % Fp.modulus := by
  decide +kernel

/-! ## `Fp8Inv.bound`, which the output bound needs

`allMax` has normalised limbs but value R − 1, above 2p. Its product still meets the value
equation, but lies far above 2p. -/

def allMax : Limbs := .ofList (List.replicate 8 (2 ^ 52 - 1))

example : ¬ val allMax < 2 * Fp.modulus := by decide +kernel

example : val (Lane.mul allMax allMax) * R % Fp.modulus = val allMax * val allMax % Fp.modulus ∧
    ¬ val (Lane.mul allMax allMax) < 2 * Fp.modulus := by
  decide +kernel

/-! ## An equivalent mutant: the low half needs no operand truncation

The low 52 bits of a product depend only on the low 52 bits of its factors, so dropping
`madd52lo`'s operand truncation changes nothing. No lemma can catch that mutant. -/

example (a b c : UInt64) : madd52lo a b c = madd52loWide a b c := by
  simp only [madd52lo, madd52loWide, lo52, ← Nat.mul_mod]

end LeanBlsSimd
