import LeanBlsSimd.Kzg.Extender.Kernel.FftWideOperands

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel.WideStage

def body (s : WideStage) (pairs : Usize) (data : Slice fr8.Fr8)
    (t : Array M512 11#usize) (n : Usize) :=
  if s.dit then fft8.Fft8.dit_wide_loop.body s.table.vectors s.table.wide s.table.short
    s.half s.offset pairs data t n
  else fft8.Fft8.dif_wide_loop.body s.table.vectors s.table.wide s.table.short
    s.half s.offset pairs data t n

theorem body_eq (s : WideStage) (pairs : Usize) (data : Slice fr8.Fr8)
    (t : Array M512 11#usize) (n : Usize) :
    s.body pairs data t n = (do
      let n1 ← n + 1#usize
      if n1 < pairs then
        let ((a,b), data1) ← s.prepare data n1
        let (p,next) ← fr8.Fr8.reduce_while_multiplying t a b
        let i ← fft8.first_of_pair n s.half
        let out ← s.finish data1 i p
        ok (cont (out,next,n1))
      else ok (done (data,t,n))) := by
  cases hd : s.dit <;> simp only [body, prepare, finish, hd,
    Bool.false_eq_true, if_false, if_true, fft8.Fft8.dit_wide_loop.body,
    fft8.Fft8.dif_wide_loop.body, bind_assoc_eq, bind_tc_ok,
    Function.uncurry_apply_pair]

theorem first_eq (s : WideStage) (h : s.Valid) (n first : Usize)
    (hn : n.val < s.table.vectors.val / 2)
    (hfirst : first.val = pairFirst s.half.val n.val) :
    fft8.first_of_pair n s.half = ok first := by
  obtain ⟨stage, hs⟩ := h.half_pow
  obtain ⟨out, ho, hv⟩ := first_of_pair_refinement n s.half stage hs
    (by have := h.size_le; omega)
  have he : out = first := UScalar.eq_of_val_eq (hv.trans hfirst.symm)
  simpa only [he] using ho

theorem body_step (s : WideStage) (h : s.Valid) (pairs n n1 : Usize)
    (hpairs : pairs.val = s.table.vectors.val / 2)
    (hn1 : n1.val = n.val + 1) (hlt : n1.val < pairs.val) :
    s.body pairs (s.state n.val (!s.dit)) (s.pending n.val) n =
      ok (cont (s.state n1.val (!s.dit), s.pending n1.val, n1)) := by
  have hn : n.val < s.table.vectors.val / 2 := by omega
  have hn1b : n1.val < s.table.vectors.val / 2 := by omega
  obtain ⟨i,j,hi,hj,hadd⟩ := h.indices n.val hn
  obtain ⟨i1,j1,hi1,hj1,hadd1⟩ := h.indices n1.val hn1b
  have hb := pairFirst_add_half_lt _ _ _ h.half_pos h.divides hn
  have hb1 := pairFirst_add_half_lt _ _ _ h.half_pos h.divides hn1b
  have hx1 : (s.state n.val (!s.dit)).val[i1.val]! = s.x n1.val := by
    rw [hi1]
    exact s.state_first n.val n1.val (!s.dit) h.half_pos (by omega)
      (Or.inr (by omega)) (by rw [h.input_length]; omega)
  have hy1 : (s.state n.val (!s.dit)).val[i1.val+s.half.val]! = s.y n1.val := by
    rw [hi1]
    exact s.state_second n.val n1.val (!s.dit) h.half_pos (by omega)
      (by rw [h.input_length]; exact hb1)
  have hp := s.prepare_refines h (s.state n.val (!s.dit)) n1 i1 hn1b
    (by simp) hi1 hx1 hy1
  let prepared := if s.dit then s.state n.val (!s.dit)
    else (s.state n.val (!s.dit)).set i1 (s.left n1.val)
  have hlen : prepared.val.length = s.input.val.length := by
    dsimp [prepared]
    split <;> simp [Slice.set, Slice.setAtNat]
  have hx : s.dit = true → prepared.val[i.val]! = s.x n.val := by
    intro hd
    simp only [prepared, hd, Bool.not_true, if_true]
    rw [hi]
    exact s.state_first n.val n.val false h.half_pos (by omega) (Or.inl rfl)
      (by rw [h.input_length]; omega)
  have hf := s.finish_refines h prepared n.val i j hn hlen hi hj hx
  have hout : (if s.dit then (prepared.set i (s.left n.val)).set j (s.right n.val)
      else prepared.set j (s.right n.val)) = s.state n1.val (!s.dit) := by
    cases hd : s.dit
    · simp only [prepared, hd, Bool.not_false, Bool.false_eq_true, if_false]
      have hne : i1 ≠ j := by
        intro he
        have hv := congrArg UScalar.val he
        rw [hi1,hj] at hv
        exact (pairs_disjoint s.half.val n1.val n.val h.half_pos (by omega)).2.1 hv
      rw [set_comm _ i1 j _ _ hne, s.state_finish_prepared n.val j h.half_pos hj]
      rw [←hn1, s.state_prepare n1.val i1 h.half_pos hi1]
    · simp only [prepared, hd, Bool.not_true, if_true]
      rw [s.state_complete n.val i j h.half_pos hi hj, hn1]
  rw [body_eq, add_eq n 1#usize n1 (by simpa using hn1)]
  simp only [bind_tc_ok, if_pos (show n1 < pairs from hlt), hp,
    FrModel.Fr8.reduce_while_multiplying_refines, Function.uncurry_apply_pair,
    first_eq s h n i hn hi]
  change (do
    let out ← s.finish prepared i (s.product n.val)
    ok (cont (out, s.pending n1.val, n1))) = _
  rw [hf, hout]
  rfl

theorem loop_refines (s : WideStage) (h : s.Valid) (pairs : Usize)
    (hpairs : pairs.val = s.table.vectors.val / 2) (remaining : Nat) :
    ∀ n : Usize, n.val + remaining + 1 = pairs.val →
      ∃ last : Usize, last.val + 1 = pairs.val ∧
        loop (fun (d,t,i) => s.body pairs d t i)
          (s.state n.val (!s.dit), s.pending n.val, n) =
          ok (s.state last.val (!s.dit), s.pending last.val, last) := by
  induction remaining with
  | zero =>
    intro n hn
    refine ⟨n, by omega, ?_⟩
    have hnadd : n + 1#usize = ok pairs := add_eq n 1#usize pairs (by simpa using hn.symm)
    rw [loop.eq_1]
    simp only [body_eq, hnadd, bind_tc_ok, lt_self_iff_false, if_false]
  | succ remaining ih =>
    intro n hn
    obtain ⟨n1, ha, hv⟩ := WP.spec_imp_exists
      (Usize.add_spec (x := n) (y := 1#usize) (by
        have := h.size_le
        simp only [UScalar.ofNatCore_val_eq]
        scalar_tac))
    simp only [UScalar.ofNatCore_val_eq] at hv
    obtain ⟨last, hl, hloop⟩ := ih n1 (by omega)
    refine ⟨last, hl, ?_⟩
    rw [loop.eq_1]
    dsimp only
    rw [body_step s h pairs n n1 hpairs hv (by omega)]
    exact hloop

theorem finish_state (s : WideStage) (h : s.Valid) (n : Nat) (first : Usize)
    (hn : n < s.table.vectors.val / 2)
    (hi : first.val = pairFirst s.half.val n) :
    s.finish (s.state n (!s.dit)) first (s.product n) = ok (s.state (n+1) false) := by
  obtain ⟨_, second, _, hs, _⟩ := h.indices n hn
  have hb := pairFirst_add_half_lt _ _ _ h.half_pos h.divides hn
  have hx : s.dit = true → (s.state n (!s.dit)).val[first.val]! = s.x n := by
    intro hd
    simp only [hd, Bool.not_true, hi]
    exact s.state_first n n false h.half_pos (by omega) (Or.inl rfl)
      (by rw [h.input_length]; omega)
  rw [s.finish_refines h _ n first second hn (by simp) hi hs hx]
  cases hd : s.dit
  · simp only [Bool.not_false, Bool.false_eq_true, if_false]
    rw [s.state_finish_prepared n second h.half_pos hs]
  · simp only [Bool.not_true, if_true]
    rw [s.state_complete n first second h.half_pos hi hs]

theorem run_refines (s : WideStage) (h : s.Valid)
    (hoffset : fr8.Fr8.multiple_of_r 2#u64 = ok s.offset) :
    (if s.dit then fft8.Fft8.dit_wide s.table s.input s.half
     else fft8.Fft8.dif_wide s.table s.input s.half) =
      ok (s.state (s.table.vectors.val/2) false) := by
  obtain ⟨pairs, hdiv, hpairs⟩ := UScalar.div_spec s.table.vectors
    (y := 2#usize) (by simp)
  simp only [UScalar.ofNatCore_val_eq] at hpairs
  have hpositive : 0 < s.table.vectors.val/2 := by
    have := h.half_pos
    have := h.half_lt
    omega
  obtain ⟨i,j,hi,hj,hadd⟩ := h.indices 0 hpositive
  have hx : s.input.val[i.val]! = s.x 0 := by simp only [hi, x]
  have hy : s.input.val[i.val+s.half.val]! = s.y 0 := by simp only [hi, y]
  have hp := s.prepare_refines h s.input 0#usize i hpositive rfl hi hx hy
  simp only [UScalar.ofNatCore_val_eq] at hp
  have hstart : (if s.dit then s.input else s.input.set i (s.left 0)) =
      s.state 0 (!s.dit) := by
    cases hd : s.dit
    · simp only [Bool.not_false, Bool.false_eq_true, if_false]
      rw [←s.state_zero, s.state_prepare 0 i h.half_pos hi]
    · simp
  rw [hstart] at hp
  obtain ⟨last, hlast, hloop⟩ := s.loop_refines h pairs hpairs (pairs.val-1)
    0#usize (by simp only [UScalar.ofNatCore_val_eq]; omega)
  have hlastb : last.val < s.table.vectors.val / 2 := by omega
  obtain ⟨lastFirst,lastSecond,hlf,hls,hladd⟩ := h.indices last.val hlastb
  have hfirst := s.first_eq h last lastFirst hlastb hlf
  have hfinish := s.finish_state h last.val lastFirst hlastb hlf
  rw [show last.val+1 = s.table.vectors.val/2 by omega] at hfinish
  cases hd : s.dit
  · have hprep : fft8.Fft8.dif_wide_operands s.table s.input s.half 0#usize s.offset =
        ok ((s.normal 0, s.factor 0), s.state 0 true) := by
      simpa only [prepare,hd,Bool.false_eq_true,if_false,Bool.not_false] using hp
    simp only [body, hd, Bool.false_eq_true, if_false, Bool.not_false,
      UScalar.ofNatCore_val_eq, pending] at hloop
    simp only [finish, hd, Bool.false_eq_true, if_false, hladd, bind_tc_ok] at hfinish
    simp only [Bool.false_eq_true, if_false, fft8.Fft8.dif_wide, hoffset,
      hdiv, bind_tc_ok, hprep, Function.uncurry_apply_pair, FrModel.Fr8.product_refines,
      fft8.Fft8.dif_wide_loop, hloop, FrModel.Fr8.reduce_refines, hfirst, hladd]
    exact hfinish
  · have hprep : fft8.Fft8.dit_wide_operands s.table s.input s.half 0#usize =
        ok (s.normal 0, s.factor 0) := by
      cases he : fft8.Fft8.dit_wide_operands s.table s.input s.half 0#usize <;>
        simp [prepare, hd, he] at hp ⊢
      exact hp
    simp only [body, hd, if_true, Bool.not_true, UScalar.ofNatCore_val_eq,
      pending, state_zero] at hloop
    simp only [finish, hd, if_true] at hfinish
    simp only [if_true, fft8.Fft8.dit_wide, hoffset, hdiv, bind_tc_ok,
      hprep, Function.uncurry_apply_pair, FrModel.Fr8.product_refines,
      fft8.Fft8.dit_wide_loop, hloop, hfirst, FrModel.Fr8.reduce_refines]
    exact hfinish

end LeanBlsSimd.Kzg.Extender.Kernel.WideStage
