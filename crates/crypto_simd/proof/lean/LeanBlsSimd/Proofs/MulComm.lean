import LeanBlsSimd.Proofs.Limbs
import Mathlib.Data.UInt

/-!
Exact commutativity of the multiplication model, without `Fp8Inv` assumptions. The product
rows form a symmetric convolution under wrapping `UInt64` addition; reduction and carries
then receive identical accumulators. This permits operand swaps in exact refinement proofs,
where equality of the represented field elements alone would not suffice.
-/

namespace LeanBlsSimd.Lane

private def contribution (a b : UInt64) (i j k : Nat) : UInt64 :=
  (if k = i + j then UInt64.ofNat (lo52 a * lo52 b % 2 ^ 52) else 0) +
  (if k = i + j + 1 then UInt64.ofNat (lo52 a * lo52 b / 2 ^ 52) else 0)

private def rowContribution (a : Limbs) (b : UInt64) (i : Fin LIMBS) (k : Nat) : UInt64 :=
  ((List.finRange LIMBS).map fun (j : Fin LIMBS) => contribution a[j] b i j k).sum

private theorem get_muladd_row (t : Acc) (a : Limbs) (b : UInt64) (i : Fin LIMBS)
    (k : Nat) (hk : k < 2 * LIMBS + 1) :
    (muladd_row t a b i)[k] = t[k] + rowContribution a b i k := by
  unfold muladd_row rowContribution
  generalize List.finRange LIMBS = js
  induction js generalizing t with
  | nil => simp
  | cons j js ih =>
    simp only [List.foldl_cons, ih, List.map_cons, List.sum_cons, ← UInt64.add_assoc]
    congr 1
    by_cases h : k = i.val + j.val
    · subst k; simp [contribution, madd52lo, madd52hi]
    · by_cases h' : k = i.val + j.val + 1
      · subst k; simp [contribution, madd52lo, madd52hi]
      · simp [contribution, madd52lo, madd52hi, h, h', Ne.symm h, Ne.symm h']

private def productAcc (a b : Limbs) : Acc :=
  (List.finRange LIMBS).foldl (fun t (i : Fin LIMBS) => muladd_row t a b[i] i)
    (.replicate _ zero)

private theorem productAcc_get (a b : Limbs) (k : Nat) (hk : k < 2 * LIMBS + 1) :
    (productAcc a b)[k] =
      ((List.finRange LIMBS).map fun (i : Fin LIMBS) => rowContribution a b[i] i k).sum := by
  simp only [productAcc, finRange_LIMBS, List.foldl_cons, List.foldl_nil, ↓get_muladd_row]
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    Vector.getElem_replicate]
  simp [zero, LIMBS, UInt64.add_assoc]

private theorem productAcc_comm (a b : Limbs) : productAcc a b = productAcc b a := by
  apply Vector.ext
  intro k hk
  simp only [productAcc_get, rowContribution]
  simp only [← Fin.sum_univ_def]
  rw [Finset.sum_comm]
  simp only [contribution, Nat.add_comm, Nat.mul_comm]

theorem mulAcc_comm (a b : Limbs) : mulAcc a b = mulAcc b a := by
  have h := productAcc_comm a b
  simp only [productAcc, finRange_LIMBS, List.foldl_cons, List.foldl_nil, Fin.getElem_fin,
    val_fin_LIMBS] at h
  simp only [mulAcc, h]

theorem mul_comm (a b : Limbs) : mul a b = mul b a := by
  simp only [mul, mulAcc_comm a b]

end LeanBlsSimd.Lane

namespace LeanBlsSimd.Fp8

theorem mul_comm (a b : Fp8) : a.mul b = b.mul a := by
  simp only [mul, Lane.mul_comm]

end LeanBlsSimd.Fp8
