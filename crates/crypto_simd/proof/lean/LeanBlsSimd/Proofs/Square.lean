import LeanBlsSimd.Proofs.Limbs
import Mathlib.Data.UInt
import Mathlib.Tactic.Abel

/-!
The triangular squaring accumulator equals the full multiplication accumulator,
including when the 64-bit additions wrap.
-/

namespace LeanBlsSimd.Lane

def productAcc (a b : Limbs) : Acc :=
  let t : Acc := .replicate _ zero
  let t := muladd_row t a b[0] 0
  let t := muladd_row t a b[1] 1
  let t := muladd_row t a b[2] 2
  let t := muladd_row t a b[3] 3
  let t := muladd_row t a b[4] 4
  let t := muladd_row t a b[5] 5
  let t := muladd_row t a b[6] 6
  muladd_row t a b[7] 7

def square_row (t : Acc) (a : Limbs) (i : Fin LIMBS) : Acc :=
  ((List.finRange LIMBS).drop (i.val + 1)).foldl (init := t) fun t (j : Fin LIMBS) =>
    let t := t.set (i.val + j.val) (madd52lo t[i.val + j.val] a[i] a[j])
    t.set (i.val + j.val + 1) (madd52hi t[i.val + j.val + 1] a[i] a[j])

def square_diag (t : Acc) (a : Limbs) (i : Fin LIMBS) : Acc :=
  let t := t.set (2 * i.val) (madd52lo t[2 * i.val] a[i] a[i])
  t.set (2 * i.val + 1) (madd52hi t[2 * i.val + 1] a[i] a[i])

def squareAcc (a : Limbs) : Acc :=
  let t : Acc := .replicate _ zero
  let t := square_row t a 0
  let t := square_row t a 1
  let t := square_row t a 2
  let t := square_row t a 3
  let t := square_row t a 4
  let t := square_row t a 5
  let t := square_row t a 6
  let t := t.map fun x => x + x
  (List.finRange LIMBS).foldl (fun t i => square_diag t a i) t

private def contribution (a b : UInt64) (i j k : Nat) : UInt64 :=
  (if k = i + j then UInt64.ofNat (lo52 a * lo52 b % 2 ^ 52) else 0) +
  (if k = i + j + 1 then UInt64.ofNat (lo52 a * lo52 b / 2 ^ 52) else 0)

private theorem contribution_comm_values (a b : UInt64) (i j k : Nat) :
    contribution a b i j k = contribution b a i j k := by
  simp [contribution, Nat.mul_comm]

private theorem contribution_comm_indices (a b : UInt64) (i j k : Nat) :
    contribution a b i j k = contribution a b j i k := by
  simp [contribution, Nat.add_comm]

private theorem get_muladd_row (t : Acc) (a : Limbs) (b : UInt64) (i : Fin LIMBS)
    (k : Nat) (hk : k < 2 * LIMBS + 1) :
    (muladd_row t a b i)[k] = t[k] +
      ((List.finRange LIMBS).map fun (j : Fin LIMBS) => contribution a[j] b i j k).sum := by
  unfold muladd_row
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

private theorem get_square_row (t : Acc) (a : Limbs) (i : Fin LIMBS)
    (k : Nat) (hk : k < 2 * LIMBS + 1) :
    (square_row t a i)[k] = t[k] +
      (((List.finRange LIMBS).drop (i.val + 1)).map fun (j : Fin LIMBS) =>
        contribution a[i] a[j] i j k).sum := by
  unfold square_row
  generalize (List.finRange LIMBS).drop (i.val + 1) = js
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

private theorem get_square_diag (t : Acc) (a : Limbs) (i : Fin LIMBS)
    (k : Nat) (hk : k < 2 * LIMBS + 1) :
    (square_diag t a i)[k] = t[k] + contribution a[i] a[i] i i k := by
  by_cases h : k = 2 * i.val
  · subst k; simp [square_diag, contribution, madd52lo, madd52hi, two_mul]
  · by_cases h' : k = 2 * i.val + 1
    · subst k; simp [square_diag, contribution, madd52lo, madd52hi, two_mul]
    · simp [square_diag, contribution, madd52lo, madd52hi, h, h',
        Ne.symm h, Ne.symm h', ← two_mul]

attribute [local irreducible] contribution muladd_row square_row square_diag squareAcc productAcc

theorem squareAcc_eq_productAcc (a : Limbs) : squareAcc a = productAcc a a := by
  apply Vector.ext
  intro k hk
  simp only [squareAcc, productAcc, finRange_LIMBS, List.foldl_cons, List.foldl_nil,
    get_square_diag, Vector.getElem_map, get_square_row, get_muladd_row,
    Vector.getElem_replicate]
  simp only [val_fin_LIMBS, Nat.reduceAdd, List.drop_succ_cons,
    List.drop_zero, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    Fin.getElem_fin, zero, UInt64.add_zero, UInt64.zero_add]
  -- Abstract the limb reads so index proof terms do not affect symmetric product ordering.
  generalize a[0] = a0, a[1] = a1, a[2] = a2, a[3] = a3,
    a[4] = a4, a[5] = a5, a[6] = a6, a[7] = a7
  simp only [contribution_comm_values, contribution_comm_indices]
  abel

end LeanBlsSimd.Lane
