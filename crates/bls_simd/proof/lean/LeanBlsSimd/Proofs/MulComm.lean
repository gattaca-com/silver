import LeanBlsSimd.Proofs.Limbs

namespace LeanBlsSimd.Lane

private theorem add_left_comm64 (a b c : UInt64) : a + (b + c) = b + (a + c) := by
  rw [← UInt64.add_assoc, UInt64.add_comm a b, UInt64.add_assoc]

private def contribution (a b : UInt64) (i j k : Nat) : UInt64 :=
  (if k = i + j then UInt64.ofNat (lo52 a * lo52 b % 2 ^ 52) else 0) +
  (if k = i + j + 1 then UInt64.ofNat (lo52 a * lo52 b / 2 ^ 52) else 0)

private theorem get_maddStep (x y : Fin LIMBS → UInt64) (i j : Fin LIMBS)
    (t : Acc) (k : Nat) (hk : k < 2 * LIMBS + 1) :
    (maddStep x y i t j)[k] = t[k] + contribution (x j) (y j) i j k := by
  by_cases h : k = i.val + j.val
  · subst k
    simp [maddStep, contribution, madd52lo, madd52hi]
  · by_cases h' : k = i.val + j.val + 1
    · subst k
      simp [maddStep, contribution, madd52lo, madd52hi]
    · simp [maddStep, contribution, madd52lo, madd52hi, h, h', Ne.symm h, Ne.symm h']

private theorem get_fold_maddStep (x y : Fin LIMBS → UInt64) (i : Fin LIMBS)
    (js : List (Fin LIMBS)) (t : Acc) (k : Nat) (hk : k < 2 * LIMBS + 1) :
    (js.foldl (maddStep x y i) t)[k] =
      t[k] + (js.map fun j => contribution (x j) (y j) i j k).sum := by
  induction js generalizing t with
  | nil => simp
  | cons j js ih => simp [List.foldl_cons, ih, get_maddStep, UInt64.add_assoc]

private def rowContribution (a : Limbs) (b : UInt64) (i : Fin LIMBS) (k : Nat) : UInt64 :=
  ((List.finRange LIMBS).map fun (j : Fin LIMBS) => contribution a[j] b i j k).sum

private theorem get_muladd_row (t : Acc) (a : Limbs) (b : UInt64) (i : Fin LIMBS)
    (k : Nat) (hk : k < 2 * LIMBS + 1) :
    (muladd_row t a b i)[k] =
      t[k] + rowContribution a b i k :=
  get_fold_maddStep _ _ _ _ _ _ _

private def productAcc (a b : Limbs) : Acc :=
  let t : Acc := .replicate _ zero
  let t := muladd_row t a b[0] 0
  let t := muladd_row t a b[1] 1
  let t := muladd_row t a b[2] 2
  let t := muladd_row t a b[3] 3
  let t := muladd_row t a b[4] 4
  let t := muladd_row t a b[5] 5
  let t := muladd_row t a b[6] 6
  muladd_row t a b[7] 7

private theorem sum_add {α : Type} (xs : List α) (f g : α → UInt64) :
    (xs.map fun x => f x + g x).sum = (xs.map f).sum + (xs.map g).sum := by
  induction xs with
  | nil => simp
  | cons x xs ih => simp [ih, UInt64.add_assoc, add_left_comm64]

private theorem sum_swap {α β : Type} (xs : List α) (ys : List β) (f : α → β → UInt64) :
    (xs.map fun x => (ys.map (f x)).sum).sum =
      (ys.map fun y => (xs.map fun x => f x y).sum).sum := by
  induction xs with
  | nil =>
    simp only [List.map_nil, List.sum_nil]
    induction ys with
    | nil => rfl
    | cons y ys ih => simpa only [List.map_cons, List.sum_cons, UInt64.zero_add] using ih
  | cons x xs ih => simp [sum_add, ih]

private theorem productAcc_get (a b : Limbs) (k : Nat) (hk : k < 2 * LIMBS + 1) :
    (productAcc a b)[k] =
      ((List.finRange LIMBS).map fun (i : Fin LIMBS) => rowContribution a b[i] i k).sum := by
  simp only [productAcc, ↓get_muladd_row]
  simp only [finRange_LIMBS, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    Vector.getElem_replicate]
  simp [zero, LIMBS, UInt64.add_assoc]
  rfl

private theorem productAcc_comm (a b : Limbs) : productAcc a b = productAcc b a := by
  apply Vector.ext
  intro k hk
  simp only [productAcc_get, rowContribution]
  rw [sum_swap]
  congr 1
  apply List.map_congr_left
  intro i hi
  congr 1
  apply List.map_congr_left
  intro j hj
  simp only [contribution, Nat.add_comm i.val j.val, Nat.mul_comm]

theorem mulAcc_comm (a b : Limbs) : mulAcc a b = mulAcc b a := by
  have h := productAcc_comm a b
  dsimp only [productAcc] at h
  simp only [mulAcc, h]

theorem mul_comm (a b : Limbs) : mul a b = mul b a := by
  simp only [mul, mulAcc_comm a b]

end LeanBlsSimd.Lane

namespace LeanBlsSimd.Fp8

theorem mul_comm (a b : Fp8) : a.mul b = b.mul a := by
  simp only [mul, Lane.mul_comm]

end LeanBlsSimd.Fp8
