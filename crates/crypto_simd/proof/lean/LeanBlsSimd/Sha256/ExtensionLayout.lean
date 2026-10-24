import LeanBlsSimd.Sha256.ExtensionBytes
import LeanBlsSimd.Sha256.ExtensionRounds

open Aeneas Aeneas.Std Result
open silver_crypto_simd

namespace LeanBlsSimd.Sha256.Extensions

theorem shuffle_b1 (a b c d : UInt32) :
    _mm_shuffle_epi32 0xb1 #v[a,b,c,d] = #v[b,a,d,c] := by
  apply Vector.ext
  intro i hi
  interval_cases i <;> rfl

theorem shuffle_reverse (a b c d : UInt32) :
    _mm_shuffle_epi32 0x1b #v[a,b,c,d] = #v[d,c,b,a] := by
  apply Vector.ext
  intro i hi
  interval_cases i <;> rfl

theorem initial_layout (s : Spec.RoundState) :
    let dcba := #v[s.1,s.2.1,s.2.2.1,s.2.2.2.1]
    let hgfe := #v[s.2.2.2.2.1,s.2.2.2.2.2.1,s.2.2.2.2.2.2.1,s.2.2.2.2.2.2.2]
    let cdab := _mm_shuffle_epi32 0xb1 dcba
    let efgh := _mm_shuffle_epi32 0x1b hgfe
    (_mm_alignr_epi8 8 cdab efgh,_mm_blend_epi16 0xf0 efgh cdab) = (abef s,cdgh s) := by
  dsimp only
  rw [shuffle_b1,shuffle_reverse,alignr_eight,blend_f0]
  rfl

theorem final_layout (s : Spec.RoundState) :
    let feba := _mm_shuffle_epi32 0x1b (abef s)
    let dchg := _mm_shuffle_epi32 0xb1 (cdgh s)
    (_mm_blend_epi16 0xf0 feba dchg,_mm_alignr_epi8 8 dchg feba) =
      (#v[s.1,s.2.1,s.2.2.1,s.2.2.2.1],
       #v[s.2.2.2.2.1,s.2.2.2.2.2.1,s.2.2.2.2.2.2.1,s.2.2.2.2.2.2.2]) := by
  dsimp only [abef,cdgh]
  rw [shuffle_reverse,shuffle_b1,blend_f0,alignr_eight]
  rfl

theorem load_words_refines (v : M128) :
    sha256.extensions.load_words (toArray word v) = ok v := by
  unfold sha256.extensions.load_words
  apply congrArg ok
  apply Vector.ext
  intro i hi
  simp only [Vector.getElem_ofFn,toArray_val,List.getElem_map,Vector.getElem_toList]
  rfl

theorem store_words_refines (v : M128) :
    sha256.extensions.store_words v = ok (toArray word v) := rfl

theorem feed_forward (state : _root_.Array UInt32) (s : Spec.RoundState) :
    let before := Spec.stateWords state
    let after := Spec.stateWords (Spec.feedForward state s)
    (_mm_add_epi32 (abef s) (abef before),_mm_add_epi32 (cdgh s) (cdgh before)) =
      (abef after,cdgh after) := by
  rcases s with ⟨a,b,c,d,e,f,g,h⟩
  dsimp only
  apply Prod.ext
  all_goals
    apply Vector.ext
    intro i hi
    interval_cases i <;>
      norm_num only [abef,cdgh,Spec.stateWords,Spec.feedForward,_mm_add_epi32,
        Vector.getElem_ofFn,Vector.getElem_mk,List.getElem_toArray,
        List.getElem_cons_zero,List.getElem_cons_succ]
  all_goals exact UInt32.add_comm _ _

end LeanBlsSimd.Sha256.Extensions
