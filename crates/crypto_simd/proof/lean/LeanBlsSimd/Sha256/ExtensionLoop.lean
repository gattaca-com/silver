import LeanBlsSimd.Sha256.Schedule
import LeanBlsSimd.Sha256.ExtensionSchedule
import LeanBlsSimd.Sha256.ExtensionLayout
import LeanBlsSimd.Sha256.PortableCompress

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd

namespace LeanBlsSimd.Sha256.Extensions

set_option maxHeartbeats 120000
set_option maxRecDepth 2048
attribute [local irreducible] Spec.schedule

def window (w : _root_.Array UInt32) (q : Nat) : Array M128 4#usize :=
  Array.make 4#usize [quad w (4*min q 15),quad w (4*min (q+1) 15),
    quad w (4*min (q+2) 15),quad w (4*min (q+3) 15)] (by rfl)

def advance (w : Array M128 4#usize) (q : Nat) : Array M128 4#usize :=
  let a := w.val[0]!; let b := w.val[1]!; let c := w.val[2]!; let d := w.val[3]!
  Array.make 4#usize [b,c,d,if q<12 then
    _mm_sha256msg2_epu32 (_mm_add_epi32 (_mm_sha256msg1_epu32 a b) (_mm_alignr_epi8 4 d c)) d
    else d] (by rfl)

theorem advance_window (buf : ByteArray) (off q : Nat) (hq : q < 16) :
    advance (window (Spec.schedule buf off) q) q = window (Spec.schedule buf off) (q+1) := by
  apply Subtype.ext
  by_cases he : q < 12
  · simp (disch := omega) only [advance,window,Array.make,List.getElem!_cons_zero,
      List.getElem!_cons_succ,if_pos,Nat.min_eq_left]
    have hm := schedule_four (Spec.schedule buf off) (4*q+16) (by omega) (by simp; omega)
    simp (disch := omega) only [Spec.schedule_step_eq_self] at hm
    simp only [show 4*q+16-16=4*q by omega,show 4*q+16-12=4*(q+1) by omega,
      show 4*q+16-8=4*(q+2) by omega,show 4*q+16-4=4*(q+3) by omega] at hm
    rw [hm]
    simp only [Nat.add_assoc,Nat.reduceAdd,show 4*q+16=4*(q+4) by omega]
  · have hlo : 12 ≤ q := by omega
    interval_cases q <;> rfl

theorem add_quad (w k : _root_.Array UInt32) (t : Nat) :
    _mm_add_epi32 (quad w t) (quad k t) =
      #v[k[t]!+w[t]!,k[t+1]!+w[t+1]!,k[t+2]!+w[t+2]!,k[t+3]!+w[t+3]!] := by
  apply Vector.ext
  intro i hi
  interval_cases i <;>
    norm_num only [_mm_add_epi32,quad,Vector.getElem_ofFn,Vector.getElem_mk,List.getElem_toArray,
      List.getElem_cons_zero,List.getElem_cons_succ]
  all_goals exact UInt32.add_comm _ _

theorem quad_rounds (w : _root_.Array UInt32) (q : Nat) (s : Spec.RoundState) :
    let wk := _mm_add_epi32 (quad w (4*q)) (quad Spec.constants (4*q))
    let c := _mm_sha256rnds2_epu32 (cdgh s) (abef s) wk
    (_mm_sha256rnds2_epu32 (abef s) c (_mm_shuffle_epi32 14 wk),c) =
      (abef (Spec.rounds w (4*q) 4 s),cdgh (Spec.rounds w (4*q) 4 s)) := by
  rw [add_quad]
  simpa only [Spec.rounds,List.range',List.foldl_cons,List.foldl_nil,Nat.add_assoc,Nat.reduceAdd]
    using four_rounds s Spec.constants[4*q]! Spec.constants[4*q+1]!
      Spec.constants[4*q+2]! Spec.constants[4*q+3]!
      w[4*q]! w[4*q+1]! w[4*q+2]! w[4*q+3]!

attribute [local irreducible] Spec.rounds quad abef cdgh

theorem quad_step (buf : ByteArray) (off : Nat) (s : Spec.RoundState) (q : Usize) (hq : q.val < 16) :
    ∃ next, sha256.extensions.compress_blocks_loop0_loop1.body (abef s) (cdgh s)
      (window (Spec.schedule buf off) q.val) q =
        ok (cont (abef (Spec.rounds (Spec.schedule buf off) (4*q.val) 4 s),
          cdgh (Spec.rounds (Spec.schedule buf off) (4*q.val) 4 s),
          window (Spec.schedule buf off) (q.val+1),next)) ∧ next.val = q.val+1 := by
  let next : Usize := UScalar.ofNatCore (q.val+1) (by scalar_tac)
  refine ⟨next,?_,rfl⟩
  have hq' : q < 16#usize := hq
  simp only [sha256.extensions.compress_blocks_loop0_loop1.body,hq',if_true]
  simp (disch := scalar_tac) only [mul_ok,add_ok,bind_tc_ok,UScalar.ofNatCore_val_eq,
    Portable.index_word]
  rw [Portable.constants_refines]
  have hk : (Array.make 4#usize [word Spec.constants[4*q.val]!,word Spec.constants[4*q.val+1]!,
      word Spec.constants[4*q.val+2]!,word Spec.constants[4*q.val+3]!] (by rfl)) =
      toArray word (quad Spec.constants (4*q.val)) := by unfold quad; rfl
  rw [hk,load_words_refines]
  simp (disch := scalar_tac) only [bind_tc_ok,index_usize_eq]
  norm_num only [UScalar.ofNatCore_val_eq]
  simp only [window,Array.make,List.getElem_cons_zero,List.getElem_cons_succ,
    core.core_arch.x86.sse2._mm_add_epi32,core.core_arch.x86.sha._mm_sha256rnds2_epu32,
    core.core_arch.x86.sse2._mm_shuffle_epi32,bind_tc_ok]
  have hw0 : min q.val 15 = q.val := Nat.min_eq_left (by omega)
  rw [hw0]
  have hr := quad_rounds (Spec.schedule buf off) q.val s
  dsimp only at hr
  have ha := congrArg Prod.fst hr
  have hc := congrArg Prod.snd hr
  dsimp only at ha hc
  simp only [show (I32.bv 14#i32).toNat = 14 by decide +kernel]
  rw [ha,hc]
  have hn := advance_window buf off q.val hq
  unfold advance window at hn
  by_cases he : q.val < 12
  · have he' : q < 12#usize := he
    simp only [he',if_true,core.core_arch.x86.sha._mm_sha256msg1_epu32,
      core.core_arch.x86.sha._mm_sha256msg2_epu32,core.core_arch.x86.ssse3._mm_alignr_epi8,
      bind_tc_ok]
    simp only [Array.make,List.getElem!_cons_zero,List.getElem!_cons_succ,he,if_true,hw0] at hn
    simp only [show (I32.bv 4#i32).toNat = 4 by decide +kernel]
    rw [hn]
  · have he' : ¬ q < 12#usize := he
    simp only [he',if_false,bind_tc_ok]
    simp only [Array.make,List.getElem!_cons_zero,List.getElem!_cons_succ,he,if_false,hw0] at hn
    rw [hn]

theorem quad_loop_refines (buf : ByteArray) (off : Nat) (s : Spec.RoundState)
    (q : Usize) (hq : q.val ≤ 16) :
    sha256.extensions.compress_blocks_loop0_loop1 (abef s) (cdgh s)
      (window (Spec.schedule buf off) q.val) q =
      ok (abef (Spec.rounds (Spec.schedule buf off) (4*q.val) (64-4*q.val) s),
        cdgh (Spec.rounds (Spec.schedule buf off) (4*q.val) (64-4*q.val) s)) := by
  induction hn : 16-q.val generalizing s q with
  | zero =>
    have hstop : ¬ q < 16#usize := by change ¬ q.val < 16; omega
    have hz : 64-4*q.val = 0 := by omega
    rw [sha256.extensions.compress_blocks_loop0_loop1,loop.eq_1]
    simp only [sha256.extensions.compress_blocks_loop0_loop1.body,hstop,if_false,hz]
    unfold Spec.rounds
    rfl
  | succ n ih =>
    obtain ⟨next,hbody,hnext⟩ := quad_step buf off s q (by omega)
    have hr := ih (Spec.rounds (Spec.schedule buf off) (4*q.val) 4 s) next (by omega) (by omega)
    have hstart : 4*next.val = 4*q.val+4 := by omega
    rw [hstart,← Spec.rounds_append] at hr
    have hc : 4+(64-(4*q.val+4)) = 64-4*q.val := by omega
    rw [hc] at hr
    rw [sha256.extensions.compress_blocks_loop0_loop1,loop.eq_1]
    simpa only [hbody,hnext] using hr

end LeanBlsSimd.Sha256.Extensions
