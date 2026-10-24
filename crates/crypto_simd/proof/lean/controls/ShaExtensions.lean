import LeanBlsSimd.Sha256.ExtensionLayout
import LeanBlsSimd.Sha256.ExtensionSchedule

open LeanBlsSimd LeanBlsSimd.Sha256 LeanBlsSimd.Sha256.Extensions

namespace LeanBlsSimd.Controls.ShaExtensions

private def s : Spec.RoundState := Spec.stateWords Spec.initialState
private def wk : M128 := #v[Spec.constants[0]!,Spec.constants[1]!+1,
  Spec.constants[2]!+2,Spec.constants[3]!+3]

theorem swapped_state_vectors_rejected : abef s ≠ cdgh s := by decide +kernel

theorem omitted_second_shuffle_rejected :
    _mm_sha256rnds2_epu32 (abef s) (_mm_sha256rnds2_epu32 (cdgh s) (abef s) wk) wk ≠
      abef (Spec.round Spec.constants[3]! 3 (Spec.round Spec.constants[2]! 2
        (Spec.round Spec.constants[1]! 1 (Spec.round Spec.constants[0]! 0 s)))) := by
  decide +kernel

private def a : M128 := #v[1,2,3,4]
private def b : M128 := #v[5,6,7,8]
private def c : M128 := #v[9,10,11,12]
private def d : M128 := #v[13,14,15,16]

theorem old_message_dependency_rejected :
    (_mm_sha256msg2_epu32 (_mm_add_epi32 (_mm_sha256msg1_epu32 a b)
      (_mm_alignr_epi8 4 d c)) d)[2] ≠
      a[2] + Spec.smallSigma0 a[3] + c[3] + Spec.smallSigma1 d[0] := by
  decide +kernel

end LeanBlsSimd.Controls.ShaExtensions

#print axioms LeanBlsSimd.Sha256.Extensions.four_rounds
#print axioms LeanBlsSimd.Sha256.Extensions.initial_layout
#print axioms LeanBlsSimd.Sha256.Extensions.final_layout
#print axioms LeanBlsSimd.Sha256.Extensions.feed_forward
#print axioms LeanBlsSimd.Sha256.Extensions.byte_load_get
#print axioms LeanBlsSimd.Sha256.Extensions.schedule_four
