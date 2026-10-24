import LeanBlsSimd.Sha256.Blocks

namespace LeanBlsSimd.Sha256.Spec

def fill (f : Array UInt32 → Nat → UInt32) (w : Array UInt32) (start count : Nat) : Array UInt32 :=
  (List.range' start count).foldl (fun w i => w.set! i (f w i)) w

@[simp] theorem fill_size (f : Array UInt32 → Nat → UInt32) (w : Array UInt32) (start count : Nat) :
    (fill f w start count).size = w.size := by
  induction count generalizing w start with
  | zero => rfl
  | succ n ih => simpa only [fill,List.range',List.foldl_cons,Array.set!_eq_setIfInBounds,
      Array.size_setIfInBounds] using ih (w.set! start (f w start)) (start+1)

theorem read_set (w : Array UInt32) (i j : Nat) (x : UInt32) (hj : j < w.size) :
    (w.set! i x)[j]! = if i=j then x else w[j]! := by
  rw [getElem!_pos (w.set! i x) j (by simpa using hj),getElem!_pos w j hj]
  simp only [Array.set!_eq_setIfInBounds,Array.getElem_setIfInBounds hj]

theorem fill_before (f : Array UInt32 → Nat → UInt32) (w : Array UInt32) (start count i : Nat)
    (hi : i < start) (hw : i < w.size) : (fill f w start count)[i]! = w[i]! := by
  induction count generalizing w start with
  | zero => rfl
  | succ n ih =>
    change (fill f (w.set! start (f w start)) (start+1) n)[i]! = _
    rw [ih _ _ (by omega) (by simpa using hw),read_set _ _ _ _ hw,if_neg (by omega)]

theorem fill_split (f : Array UInt32 → Nat → UInt32) (w : Array UInt32) (start m n : Nat) :
    fill f w start (m+n) = fill f (fill f w start m) (start+m) n := by
  simp only [fill,← List.range'_append,Nat.one_mul,List.foldl_append]

theorem fill_current (f : Array UInt32 → Nat → UInt32) (w : Array UInt32) (start count : Nat)
    (hc : 0 < count) (hw : start < w.size) : (fill f w start count)[start]! = f w start := by
  obtain ⟨n,rfl⟩ := Nat.exists_eq_succ_of_ne_zero (by omega : count ≠ 0)
  change (fill f (w.set! start (f w start)) (start+1) n)[start]! = _
  rw [fill_before _ _ _ _ _ (by omega) (by simpa using hw),read_set _ _ _ _ hw,if_pos rfl]

def scheduleValue (w : Array UInt32) (t : Nat) : UInt32 :=
  w[t-16]! + smallSigma0 w[t-15]! + w[t-7]! + smallSigma1 w[t-2]!

def loaded (buf : ByteArray) (off : Nat) : Array UInt32 :=
  fill (fun _ t => big32 buf (off+4*t)) (Array.replicate 64 0) 0 16

theorem schedule_eq_fill (buf : ByteArray) (off : Nat) :
    schedule buf off = fill scheduleValue (loaded buf off) 16 48 := rfl

@[simp] theorem loaded_size (buf : ByteArray) (off : Nat) : (loaded buf off).size = 64 := by
  simp [loaded]

@[simp] theorem schedule_size (buf : ByteArray) (off : Nat) : (schedule buf off).size = 64 := by
  rw [schedule_eq_fill]; simp

theorem loaded_get (buf : ByteArray) (off i : Nat) (hi : i < 16) :
    (loaded buf off)[i]! = big32 buf (off+4*i) := by
  unfold loaded
  rw [show 16 = i+(16-i) by omega,fill_split]
  simpa only [Nat.zero_add] using fill_current
    (fun _ t => big32 buf (off+4*t))
    (fill (fun _ t => big32 buf (off+4*t)) (Array.replicate 64 0) 0 i)
    i (16-i) (by omega) (by simp; omega)

theorem schedule_get_initial (buf : ByteArray) (off i : Nat) (hi : i < 16) :
    (schedule buf off)[i]! = big32 buf (off+4*i) := by
  rw [schedule_eq_fill,fill_before _ _ _ _ _ hi (by simp; omega),loaded_get _ _ _ hi]

theorem schedule_get_recurrence (buf : ByteArray) (off t : Nat) (hlo : 16 ≤ t) (hi : t < 64) :
    (schedule buf off)[t]! = scheduleValue (schedule buf off) t := by
  let pre := fill scheduleValue (loaded buf off) 16 (t-16)
  have hp : pre.size = 64 := by simp [pre]
  have hs : schedule buf off = fill scheduleValue pre t (64-t) := by
    rw [schedule_eq_fill,show 48 = (t-16)+(64-t) by omega,fill_split]
    simp only [show 16+(t-16)=t by omega]
    rfl
  rw [hs,fill_current _ _ _ _ (by omega) (by omega)]
  unfold scheduleValue
  simp (disch := omega) only [fill_before]

theorem set_read_self (w : Array UInt32) (i : Nat) (hi : i < w.size) : w.set! i w[i]! = w := by
  rw [getElem!_pos w i hi]
  simp only [Array.set!_eq_setIfInBounds,Array.setIfInBounds,dif_pos hi,Array.set_getElem_self]

theorem schedule_step_eq_self (buf : ByteArray) (off t : Nat) (hlo : 16 ≤ t) (hi : t < 64) :
    scheduleStep (schedule buf off) t = schedule buf off := by
  change (schedule buf off).set! t (scheduleValue (schedule buf off) t) = _
  rw [← schedule_get_recurrence buf off t hlo hi]
  exact set_read_self _ _ (by simpa using hi)

end LeanBlsSimd.Sha256.Spec
