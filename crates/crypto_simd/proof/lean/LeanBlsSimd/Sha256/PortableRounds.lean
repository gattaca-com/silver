import LeanBlsSimd.Sha256.Words

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd
open private EthLib.Cryptography.Bls.Sha256.K from EthLib.Cryptography.Bls.Sha256

namespace LeanBlsSimd.Sha256.Portable

attribute [local irreducible] Spec.round Spec.rounds

theorem constants_refines : words sha256.K = Spec.constants := by
  unfold sha256.K
  rfl

def roundArgs (s : Spec.RoundState) : U32 × U32 × U32 × U32 × U32 × U32 × U32 × U32 :=
  (word s.1,word s.2.1,word s.2.2.1,word s.2.2.2.1,word s.2.2.2.2.1,
    word s.2.2.2.2.2.1,word s.2.2.2.2.2.2.1,word s.2.2.2.2.2.2.2)

def loopArgs (s : Spec.RoundState) (t : Usize) :
    U32 × U32 × U32 × U32 × U32 × U32 × U32 × U32 × Usize :=
  (word s.1,word s.2.1,word s.2.2.1,word s.2.2.2.1,word s.2.2.2.2.1,
    word s.2.2.2.2.2.1,word s.2.2.2.2.2.2.1,word s.2.2.2.2.2.2.2,t)

theorem round_step (w : Array U32 64#usize) (s : Spec.RoundState) (t : Usize)
    (ht : t.val < 64) :
    ∃ next, next.val = t.val+1 ∧
      sha256.portable.compress_loop.body w
        (word s.1) (word s.2.1) (word s.2.2.1) (word s.2.2.2.1)
        (word s.2.2.2.2.1) (word s.2.2.2.2.2.1)
        (word s.2.2.2.2.2.2.1) (word s.2.2.2.2.2.2.2) t =
      ok (cont (loopArgs (Spec.round Spec.constants[t.val]! (words w)[t.val]! s) next)) := by
  let next : Usize := UScalar.ofNatCore (t.val+1) (by scalar_tac)
  refine ⟨next,rfl,?_⟩
  have ht' : t < 64#usize := ht
  have hk := words_get sha256.K t.val ht
  rw [constants_refines] at hk
  have hw := words_get w t.val ht
  simp only [sha256.portable.compress_loop.body,ht',if_true,bigSigma1_refines,
    choose_refines,majority_refines,bigSigma0_refines,wrapping_add_word,lift,bind_tc_ok]
  rw [index_usize_eq _ _ ht]
  simp only [bind_tc_ok]
  rw [← word_ofWord (sha256.K.val[t.val]'_), ← hk,wrapping_add_word,index_usize_eq _ _ ht]
  simp only [bind_tc_ok]
  rw [← word_ofWord (w.val[t.val]'_), ← hw]
  simp only [wrapping_add_word]
  rw [add_ok _ _ (by scalar_tac)]
  simp only [bind_tc_ok]
  unfold loopArgs Spec.round
  rfl

theorem rounds_refines (w : Array U32 64#usize) (s : Spec.RoundState) (t : Usize)
    (ht : t.val ≤ 64) :
    sha256.portable.compress_loop w
      (word s.1) (word s.2.1) (word s.2.2.1) (word s.2.2.2.1)
      (word s.2.2.2.2.1) (word s.2.2.2.2.2.1)
      (word s.2.2.2.2.2.2.1) (word s.2.2.2.2.2.2.2) t =
    ok (roundArgs (Spec.rounds (words w) t.val (64-t.val) s)) := by
  induction hn : 64-t.val generalizing s t with
  | zero =>
    have hstop : ¬t < 64#usize := by change ¬t.val < 64; omega
    rw [sha256.portable.compress_loop,loop.eq_1]
    simp only [sha256.portable.compress_loop.body,hstop,if_false]
    unfold Spec.rounds
    rfl
  | succ n ih =>
    obtain ⟨next,hnext,hbody⟩ := round_step w s t (by omega)
    have hr := ih (Spec.round Spec.constants[t.val]! (words w)[t.val]! s) next
      (by omega) (by omega)
    rw [sha256.portable.compress_loop,loop.eq_1]
    dsimp only
    rw [hbody]
    change sha256.portable.compress_loop w _ _ _ _ _ _ _ _ next = _
    rw [hr]
    rw [hnext]
    unfold Spec.rounds
    rfl

end LeanBlsSimd.Sha256.Portable
