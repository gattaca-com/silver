import LeanBlsSimd.Sha256.Blocks

namespace LeanBlsSimd.Sha256.Spec

theorem set_read_self (w : Array UInt32) (i : Nat) (hi : i < w.size) : w.set! i w[i]! = w := by
  rw [getElem!_pos w i hi]
  simp only [Array.set!_eq_setIfInBounds,Array.setIfInBounds,dite_eq_left hi,Array.set_getElem_self]

theorem schedule_step_eq_self (buf : ByteArray) (off t : Nat) (hlo : 16 ≤ t) (hi : t < 64) :
    scheduleStep (schedule buf off) t = schedule buf off := by
  change (schedule buf off).set! t (scheduleValue (schedule buf off) t) = _
  rw [← schedule_get_recurrence buf off t hlo hi]
  exact set_read_self _ _ (by simpa using hi)

end LeanBlsSimd.Sha256.Spec
