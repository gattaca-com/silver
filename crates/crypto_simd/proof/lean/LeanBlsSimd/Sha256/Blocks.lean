import LeanBlsSimd.Spec.Sha256

open private EthLib.Cryptography.Bls.Sha256.big32 from EthLib.Cryptography.Bls.Sha256

namespace LeanBlsSimd.Sha256.Spec

attribute [local irreducible] compressBlock schedule round rounds feedForward

theorem foldl_congr_on {α β : Type} (xs : List α) (f g : β → α → β) (init : β)
    (h : ∀ i ∈ xs, ∀ s, f s i = g s i) : xs.foldl f init = xs.foldl g init := by
  induction xs generalizing init with
  | nil => rfl
  | cons x xs ih =>
    rw [List.foldl_cons, List.foldl_cons, h x (by simp)]
    exact ih _ (fun i hi s => h i (by simp [hi]) s)

theorem schedule_congr (b c : ByteArray) (off off' : Nat)
    (h : ∀ i < 64, b[off+i]! = c[off'+i]!) : schedule b off = schedule c off' := by
  have hfirst := foldl_congr_on (List.range' 0 16)
    (fun (w : Array UInt32) t => w.set! t (big32 b (off+4*t)))
    (fun (w : Array UInt32) t => w.set! t (big32 c (off'+4*t)))
    (Array.replicate 64 0) (by
      intro t ht w
      have ht' : t < 16 := (List.mem_range'_1.mp ht).2
      have hb : big32 b (off+4*t) = big32 c (off'+4*t) := by
        simp only [big32, EthLib.Cryptography.Bls.Sha256.big32, Nat.add_assoc]
        rw [h (4*t) (by omega), h (4*t+1) (by omega),
          h (4*t+2) (by omega), h (4*t+3) (by omega)]
      exact congrArg (w.set! t) hb)
  unfold schedule
  exact congrArg (fun w => (List.range' 16 48).foldl scheduleStep w) hfirst

theorem compressBlock_congr (s : Array UInt32) (b c : ByteArray) (off off' : Nat)
    (h : ∀ i < 64, b[off+i]! = c[off'+i]!) :
    compressBlock s b off = compressBlock s c off' := by
  rw [compressBlock_eq, compressBlock_eq, schedule_congr b c off off' h]

theorem compressBlocks_zero (s : Array UInt32) (b : ByteArray) (off : Nat) :
    compressBlocks s b off 0 = s := rfl

theorem compressBlocks_succ (s : Array UInt32) (b : ByteArray) (off n : Nat) :
    compressBlocks s b off (n+1) =
      compressBlock (compressBlocks s b off n) b (off+64*n) := by
  rw [compressBlocks_append]
  rfl

private theorem range_fold_congr {α : Type} (f g : α → Nat → α) (s : α)
    (off off' n step : Nat)
    (h : ∀ i < n, ∀ v, f v (off+step*i) = g v (off'+step*i)) :
    (List.range' off n step).foldl f s = (List.range' off' n step).foldl g s := by
  induction n with
  | zero => rfl
  | succ n ih =>
    rw [← List.range'_append (m:=n) (n:=1), ← List.range'_append (s:=off') (m:=n) (n:=1)]
    simp only [List.foldl_append, List.range', List.foldl_cons, List.foldl_nil]
    rw [ih (fun i hi v => h i (by omega) v)]
    exact h n (by omega) _

theorem compressBlocks_congr (s : Array UInt32) (b c : ByteArray) (off off' n : Nat)
    (h : ∀ i < 64*n, b[off+i]! = c[off'+i]!) :
    compressBlocks s b off n = compressBlocks s c off' n := by
  apply range_fold_congr (fun s i => compressBlock s b i) (fun s i => compressBlock s c i)
  intro i hi v
  apply compressBlock_congr
  intro j hj
  simpa only [Nat.add_assoc] using h (64*i+j) (by omega)

def bytes (xs : List UInt8) : ByteArray := xs.toByteArray

@[simp] theorem bytes_size (xs : List UInt8) : (bytes xs).size = xs.length := by
  simp [bytes]

theorem bytes_get (xs : List UInt8) (i : Nat) : (bytes xs)[i]! = xs[i]! := by
  by_cases hi : i < xs.length
  · rw [getElem!_pos (bytes xs) i (by simpa using hi), getElem!_pos xs i hi]
    exact List.getElem_toByteArray
  · rw [getElem!_neg (bytes xs) i (by simpa using hi), getElem!_neg xs i hi]

theorem compressBlocks_prefix (s : Array UInt32) (xs ys : List UInt8) (n : Nat)
    (h : 64*n ≤ xs.length) :
    compressBlocks s (bytes (xs++ys)) 0 n = compressBlocks s (bytes xs) 0 n := by
  apply compressBlocks_congr
  intro i hi
  simp only [Nat.zero_add, bytes_get]
  rw [getElem!_pos (xs++ys) i (by simp only [List.length_append]; omega),
    getElem!_pos xs i (by omega), List.getElem_append_left (by omega)]

theorem bytes_drop_get (xs : List UInt8) (start i : Nat) :
    (bytes xs)[start+i]! = (bytes (xs.drop start))[i]! := by
  simp only [bytes_get]
  by_cases hi : start+i < xs.length
  · have hd : i < (xs.drop start).length := by simp only [List.length_drop]; omega
    rw [getElem!_pos xs (start+i) hi, getElem!_pos (xs.drop start) i hd, List.getElem_drop]
  · have hd : ¬ i < (xs.drop start).length := by simp only [List.length_drop]; omega
    rw [getElem!_neg xs (start+i) hi, getElem!_neg (xs.drop start) i hd]

theorem compressBlocks_drop (s : Array UInt32) (xs : List UInt8) (start n : Nat) :
    compressBlocks s (bytes xs) start n = compressBlocks s (bytes (xs.drop start)) 0 n := by
  apply compressBlocks_congr
  intro i _
  simpa only [Nat.zero_add] using bytes_drop_get xs start i

end LeanBlsSimd.Sha256.Spec
