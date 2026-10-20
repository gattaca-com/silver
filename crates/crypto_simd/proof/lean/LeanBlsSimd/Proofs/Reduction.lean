import LeanBlsSimd.Proofs.EarlyCarry
import Mathlib.Data.UInt

/-!
The early-carry schedule leaves each consumed low limb unchanged. `SameFrom` tracks only
surviving limbs, so later rows and final carry extraction can reuse the reference reduction.
The identities hold for wrapping UInt64 arithmetic without accumulator bounds.
-/

namespace LeanBlsSimd.Reduction

abbrev Acc (n : Nat) := Vector UInt64 (2 * n + 1)

def lowStep {n : Nat} (p : Vector UInt64 n) (q : UInt64) (i : Fin n)
    (t : Acc n) (j : Fin n) : Acc n :=
  t.set (i.val + j.val) (madd52lo t[i.val + j.val] p[j] q)

def highStep {n : Nat} (p : Vector UInt64 n) (q : UInt64) (i : Fin n)
    (t : Acc n) (j : Fin n) : Acc n :=
  t.set (i.val + j.val + 1) (madd52hi t[i.val + j.val + 1] p[j] q)

def productRow {n : Nat} (t : Acc n) (p : Vector UInt64 n) (q : UInt64)
    (i : Fin n) : Acc n :=
  (List.finRange n).foldl (fun t j => highStep p q i (lowStep p q i t j) j) t

def referenceRow {n : Nat} (t : Acc n) (p : Vector UInt64 n) (pinv : UInt64)
    (i : Fin n) : Acc n :=
  let q := madd52lo 0 t[i.val] pinv
  let t := productRow t p q i
  t.set (i.val + 1) (t[i.val + 1] + srli 52 t[i.val])

def earlyRow {n : Nat} (t : Acc n) (p : Vector UInt64 n) (pinv : UInt64)
    (i : Fin n) : Acc n :=
  let q := madd52lo 0 t[i.val] pinv
  let t := t.set (i.val + 1) (t[i.val + 1] + srli 52 (t[i.val] + .ofNat (2^52 - 1)))
  let high := madd52hi 0 (p[0]'(by have := i.isLt; omega)) q
  let t := ((List.finRange n).drop 1).foldl (lowStep p q i) t
  let t := t.set (i.val + 1) (t[i.val + 1] + high)
  ((List.finRange n).drop 1).foldl (highStep p q i) t

private def lowTerm {n : Nat} (p : Vector UInt64 n) (q : UInt64) (i j : Fin n)
    (k : Nat) : UInt64 :=
  if k = i.val + j.val then madd52lo 0 p[j] q else 0

private def highTerm {n : Nat} (p : Vector UInt64 n) (q : UInt64) (i j : Fin n)
    (k : Nat) : UInt64 :=
  if k = i.val + j.val + 1 then madd52hi 0 p[j] q else 0

private theorem get_lowStep {n : Nat} (t : Acc n) (p : Vector UInt64 n) (q : UInt64)
    (i j : Fin n) (k : Nat) (hk : k < 2*n+1) :
    (lowStep p q i t j)[k] = t[k] + lowTerm p q i j k := by
  by_cases h : k = i.val + j.val
  · subst k; simp [lowStep, lowTerm, madd52lo]
  · simp [lowStep, lowTerm, h, Ne.symm h]

private theorem get_highStep {n : Nat} (t : Acc n) (p : Vector UInt64 n) (q : UInt64)
    (i j : Fin n) (k : Nat) (hk : k < 2*n+1) :
    (highStep p q i t j)[k] = t[k] + highTerm p q i j k := by
  by_cases h : k = i.val + j.val + 1
  · subst k; simp [highStep, highTerm, madd52hi]
  · simp [highStep, highTerm, h, Ne.symm h]

private theorem get_lowFold {n : Nat} (js : List (Fin n)) (t : Acc n)
    (p : Vector UInt64 n) (q : UInt64) (i : Fin n) (k : Nat) (hk : k < 2*n+1) :
    (js.foldl (lowStep p q i) t)[k] = t[k] + (js.map fun j => lowTerm p q i j k).sum := by
  induction js generalizing t with
  | nil => simp
  | cons j js ih =>
    simp only [List.foldl_cons, ih, get_lowStep, List.map_cons, List.sum_cons, UInt64.add_assoc]

private theorem get_highFold {n : Nat} (js : List (Fin n)) (t : Acc n)
    (p : Vector UInt64 n) (q : UInt64) (i : Fin n) (k : Nat) (hk : k < 2*n+1) :
    (js.foldl (highStep p q i) t)[k] = t[k] + (js.map fun j => highTerm p q i j k).sum := by
  induction js generalizing t with
  | nil => simp
  | cons j js ih =>
    simp only [List.foldl_cons, ih, get_highStep, List.map_cons, List.sum_cons, UInt64.add_assoc]

private theorem get_productFold {n : Nat} (js : List (Fin n)) (t : Acc n)
    (p : Vector UInt64 n) (q : UInt64) (i : Fin n) (k : Nat) (hk : k < 2*n+1) :
    (js.foldl (fun t j => highStep p q i (lowStep p q i t j) j) t)[k] =
      t[k] + (js.map fun j => lowTerm p q i j k).sum +
        (js.map fun j => highTerm p q i j k).sum := by
  induction js generalizing t with
  | nil => simp
  | cons j js ih =>
    simp only [List.foldl_cons, ih, get_highStep, get_lowStep, List.map_cons, List.sum_cons]
    ac_rfl

private theorem finRange_head {n : Nat} (hn : 0 < n) :
    List.finRange n = ⟨0, hn⟩ :: (List.finRange n).drop 1 := by
  have hg : (List.finRange n)[0]'(by simp [hn]) = ⟨0, hn⟩ := by
    apply Fin.ext
    simp [List.finRange]
  simpa only [List.drop_zero, Nat.zero_add, hg] using
    (List.drop_eq_getElem_cons (l := List.finRange n) (i := 0) (by simp [hn]))

private theorem tail_pos {n : Nat} (j : Fin n) (hj : j ∈ (List.finRange n).drop 1) :
    0 < j.val := by
  obtain ⟨k, hk, he⟩ := List.mem_drop_iff_getElem.mp hj
  have := congrArg Fin.val he
  simp at this
  omega

private theorem productRow_at_start {n : Nat} (t : Acc n) (p : Vector UInt64 n)
    (q : UInt64) (i : Fin n) :
    (productRow t p q i)[i.val] =
      madd52lo t[i.val] (p[0]'(by have := i.isLt; omega)) q := by
  have hn : 0 < n := by have := i.isLt; omega
  have hlo : (((List.finRange n).drop 1).map fun j => lowTerm p q i j i.val).sum = 0 := by
    apply List.sum_eq_zero
    intro x hx
    obtain ⟨j, hj, rfl⟩ := List.mem_map.mp hx
    exact if_neg (by have := tail_pos j hj; omega)
  have hhi : (((List.finRange n).drop 1).map fun j => highTerm p q i j i.val).sum = 0 := by
    apply List.sum_eq_zero
    intro x hx
    obtain ⟨j, hj, rfl⟩ := List.mem_map.mp hx
    exact if_neg (by omega)
  unfold productRow
  rw [finRange_head hn, List.foldl_cons, get_productFold]
  rw [hlo, hhi]
  simp [get_highStep, get_lowStep, lowTerm, highTerm, madd52lo]

theorem earlyRow_agrees {n : Nat} (t : Acc n) (p : Vector UInt64 n) (pinv : UInt64)
    (i : Fin n)
    (hinv : (lo52 pinv * lo52 (p[0]'(by have := i.isLt; omega)) + 1) % 2^52 = 0)
    (k : Nat) (hk : k < 2*n+1) (hik : i.val < k) :
    (earlyRow t p pinv i)[k] = (referenceRow t p pinv i)[k] := by
  have hn : 0 < n := by have := i.isLt; omega
  have hcarry := Lane.carry_of_cleared_eq t[i.val] (p[0]'hn) pinv hinv
  unfold earlyRow referenceRow
  dsimp only
  rw [productRow_at_start, hcarry]
  simp only [get_highFold, get_lowFold, Vector.getElem_set]
  unfold productRow
  rw [finRange_head hn, List.foldl_cons]
  simp only [get_productFold, get_highStep, get_lowStep]
  simp only [lowTerm, highTerm, Nat.add_zero]
  by_cases h : k = i.val + 1
  · subst k
    simp only [↓reduceIte, show i.val + 1 ≠ i.val by omega]
    ac_rfl
  · have hki : k ≠ i.val := by omega
    simp [h, Ne.symm h, hki]

def SameFrom {n : Nat} (lo : Nat) (a b : Vector UInt64 n) : Prop :=
  ∀ (k : Nat) (hk : k < n), lo ≤ k → a[k] = b[k]

theorem SameFrom.refl {n : Nat} (lo : Nat) (a : Vector UInt64 n) : SameFrom lo a a :=
  fun _ _ _ => rfl

theorem referenceRow_congr {n : Nat} (a b : Acc n) (p : Vector UInt64 n) (pinv : UInt64)
    (i : Fin n) (h : SameFrom i.val a b) :
    SameFrom i.val (referenceRow a p pinv i) (referenceRow b p pinv i) := by
  have hi : i.val < 2*n+1 := by have := i.isLt; omega
  have hq := h i.val hi le_rfl
  unfold referenceRow
  rw [hq]
  have hp : SameFrom i.val (productRow a p (madd52lo 0 b[i.val] pinv) i)
      (productRow b p (madd52lo 0 b[i.val] pinv) i) := by
    intro k hk hik
    simp only [productRow, get_productFold, h k hk hik]
  intro k hk hik
  simp only [Vector.getElem_set]
  split_ifs
  · rw [hp _ _ (by omega), hp _ _ le_rfl]
  · exact hp k hk hik

theorem earlyRow_congr_suffix {n : Nat} (a b : Acc n) (p : Vector UInt64 n) (pinv : UInt64)
    (i : Fin n) (h : SameFrom i.val a b)
    (hinv : (lo52 pinv * lo52 (p[0]'(by have := i.isLt; omega)) + 1) % 2^52 = 0) :
    SameFrom (i.val + 1) (earlyRow a p pinv i) (referenceRow b p pinv i) := by
  intro k hk hik
  rw [earlyRow_agrees a p pinv i hinv k hk (by omega)]
  exact referenceRow_congr a b p pinv i h k hk (by omega)

def referenceRows {n : Nat} (t : Acc n) (p : Vector UInt64 n) (pinv : UInt64) : Acc n :=
  (List.finRange n).foldl (fun t i => referenceRow t p pinv i) t

def earlyRows {n : Nat} (t : Acc n) (p : Vector UInt64 n) (pinv : UInt64) : Acc n :=
  (List.finRange n).foldl (fun t i => earlyRow t p pinv i) t

theorem rows_agree {n : Nat} (hn : 0 < n) (t : Acc n) (p : Vector UInt64 n) (pinv : UInt64)
    (hinv : (lo52 pinv * lo52 (p[0]'hn) + 1) % 2^52 = 0) :
    SameFrom n (earlyRows t p pinv) (referenceRows t p pinv) := by
  suffices h : ∀ k (a b : Acc n), k ≤ n → SameFrom k a b →
      SameFrom n
        (((List.finRange n).drop k).foldl (fun t i => earlyRow t p pinv i) a)
        (((List.finRange n).drop k).foldl (fun t i => referenceRow t p pinv i) b) by
    exact h 0 t t (Nat.zero_le _) (SameFrom.refl 0 t)
  intro k
  induction he : n - k generalizing k with
  | zero =>
    intro a b hk hab
    have : k = n := by omega
    subst k
    rw [List.drop_eq_nil_of_le (as := List.finRange n) (i := n) (by simp)]
    exact hab
  | succ d ih =>
    intro a b hk hab
    have hkn : k < n := by omega
    rw [List.drop_eq_getElem_cons (by simp [hkn])]
    simp only [List.foldl_cons, List.getElem_finRange]
    exact ih (k + 1) (by omega) _ _ (by omega)
      (earlyRow_congr_suffix a b p pinv ⟨k, hkn⟩ hab hinv)

def carryStep {n : Nat} (t : Acc n) (mask : UInt64) (r : Vector UInt64 n)
    (j : Fin (n - 1)) : Vector UInt64 n :=
  let r := r.set (j.val + 1) (t[n + j.val + 1] + srli 52 r[j.val])
  r.set j.val (r[j.val] &&& mask)

def finish {n : Nat} [NeZero n] (t : Acc n) : Vector UInt64 n :=
  let r : Vector UInt64 n := .replicate n 0
  let r := r.set 0 t[n] (Nat.pos_of_ne_zero (NeZero.ne n))
  (List.finRange (n - 1)).foldl (carryStep t (.ofNat (2^52 - 1))) r

theorem finish_congr {n : Nat} [NeZero n] (a b : Acc n) (h : SameFrom n a b) :
    finish a = finish b := by
  have hs : carryStep a (.ofNat (2^52 - 1)) = carryStep b (.ofNat (2^52 - 1)) := by
    funext r j
    simp only [carryStep, h (n + j.val + 1) (by have := j.isLt; omega) (by omega)]
  simp only [finish, hs, h n (by omega) le_rfl]

theorem finish_rows_eq {n : Nat} [NeZero n] (t : Acc n) (p : Vector UInt64 n) (pinv : UInt64)
    (hinv : (lo52 pinv * lo52 (p[0]'(Nat.pos_of_ne_zero (NeZero.ne n))) + 1) % 2^52 = 0) :
    finish (earlyRows t p pinv) = finish (referenceRows t p pinv) :=
  finish_congr _ _ (rows_agree (Nat.pos_of_ne_zero (NeZero.ne n)) t p pinv hinv)

end LeanBlsSimd.Reduction
