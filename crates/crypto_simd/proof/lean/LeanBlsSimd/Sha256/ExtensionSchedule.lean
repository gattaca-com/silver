import LeanBlsSimd.Sha256.ExtensionBytes
import LeanBlsSimd.Sha256.ExtensionRounds

namespace LeanBlsSimd.Sha256.Extensions

theorem message_four (a b c d : M128) :
    _mm_sha256msg2_epu32 (_mm_add_epi32 (_mm_sha256msg1_epu32 a b)
      (_mm_alignr_epi8 4 d c)) d =
    let w16 := a[0] + Spec.smallSigma0 a[1] + c[1] + Spec.smallSigma1 d[2]
    let w17 := a[1] + Spec.smallSigma0 a[2] + c[2] + Spec.smallSigma1 d[3]
    #v[w16,w17,a[2] + Spec.smallSigma0 a[3] + c[3] + Spec.smallSigma1 w16,
      a[3] + Spec.smallSigma0 b[0] + d[0] + Spec.smallSigma1 w17] := by
  rw [alignr_four]
  apply Vector.ext
  intro i hi
  interval_cases i <;>
    norm_num only [_mm_sha256msg1_epu32,_mm_sha256msg2_epu32,_mm_add_epi32,
      smallSigma0_eq,smallSigma1_eq,Vector.getElem_ofFn,Vector.getElem_mk,List.getElem_toArray,
      List.getElem_cons_zero,List.getElem_cons_succ]
  all_goals rfl


private theorem read_set (w : Array UInt32) (i j : Nat) (x : UInt32) (hj : j < w.size) :
    (w.set! i x)[j]! = if i=j then x else w[j]! := by
  rw [getElem!_pos (w.set! i x) j (by simpa using hj),getElem!_pos w j hj]
  simp only [Array.set!_eq_setIfInBounds,Array.getElem_setIfInBounds hj]

def quad (w : Array UInt32) (t : Nat) : M128 := #v[w[t]!,w[t+1]!,w[t+2]!,w[t+3]!]

theorem schedule_four (w : Array UInt32) (t : Nat) (hlo : 16 ≤ t) (hi : t+4 ≤ w.size) :
    _mm_sha256msg2_epu32 (_mm_add_epi32 (_mm_sha256msg1_epu32 (quad w (t-16)) (quad w (t-12)))
      (_mm_alignr_epi8 4 (quad w (t-4)) (quad w (t-8)))) (quad w (t-4)) =
      quad (Spec.scheduleStep (Spec.scheduleStep (Spec.scheduleStep (Spec.scheduleStep w t) (t+1)) (t+2)) (t+3)) t := by
  rw [message_four]
  apply Vector.ext
  intro i hi4
  interval_cases i <;>
    norm_num only [quad,Vector.getElem_mk,List.getElem_toArray,List.getElem_cons_zero,List.getElem_cons_succ]
  all_goals
    simp (disch := (simp (failIfUnchanged := false) only [Array.set!_eq_setIfInBounds,Array.size_setIfInBounds]; omega)) only
      [Spec.scheduleStep,read_set,if_pos,if_neg,if_true]
  all_goals
    have hsub (k : Nat) (hk : k < 16) : t-k = t-16+(16-k) := by omega
    have hadd (j k : Nat) (hj : 0 < j) (hk : k ≤ 16) : t+j-k = t-16+(16+j-k) := by omega
    simp (disch := omega) only [hsub,hadd,Nat.add_assoc,Nat.reduceAdd,Nat.reduceSub]

end LeanBlsSimd.Sha256.Extensions
