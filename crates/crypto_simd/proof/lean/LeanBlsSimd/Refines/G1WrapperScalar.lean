import LeanBlsSimd.Refines.DecompressG1

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls core.ops.range core.iter.range

namespace LeanBlsSimd.UncompressG1

def ScalarWrites [G1Externals] (inputs : Slice (Array U8 48#usize))
    (original result : Slice (Option blst.blst_p1_affine)) (start stop : ℕ) : Prop :=
  result.val.length = original.val.length ∧
    ∀ j, j < original.val.length → result.val[j]! =
      if start ≤ j ∧ j < stop then G1Externals.uncompress inputs.val[j]! else original.val[j]!

private theorem scalarWrites_init [G1Externals] (inputs : Slice (Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine)) (start : ℕ) :
    ScalarWrites inputs out out start start := by
  simp [ScalarWrites]

private theorem scalarWrites_step [G1Externals] (inputs : Slice (Array U8 48#usize))
    (original out : Slice (Option blst.blst_p1_affine)) (start : ℕ) (i : Usize)
    (hi : i.val < original.val.length) (hstart : start ≤ i.val)
    (h : ScalarWrites inputs original out start i.val) :
    ScalarWrites inputs original
      (out.set i (G1Externals.uncompress inputs.val[i.val]!)) start (i.val + 1) := by
  refine ⟨by simpa [Slice.set, Slice.setAtNat] using h.1, ?_⟩
  intro j hj
  simp only [Slice.set, Slice.setAtNat]
  by_cases heq : i.val = j
  · subst j
    rw [List.getElem!_set _ _ _ (by have := h.1; omega)]
    simp [hstart]
  · rw [List.getElem!_set_ne out.val i.val j _ (Or.inl heq), h.2 j hj]
    have hc : (start ≤ j ∧ j < i.val) ↔ (start ≤ j ∧ j < i.val + 1) := by omega
    simp only [hc]

private theorem scalar_index [G1Externals] (inputs : Slice (Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine)) (i : Usize)
    (hi : i.val < inputs.val.length) (ho : i.val < out.val.length) :
    (do let a ← Slice.index_usize inputs i
        let v ← uncompress_in_g1_blst a
        Slice.update out i v) = ok (out.set i (G1Externals.uncompress inputs.val[i.val]!)) := by
  simp [Slice.index_usize, hi, uncompress_in_g1_blst,
    Slice.update, ho, Slice.set, Slice.setAtNat]

private theorem range_runs {S : Type}
    (body : Range Usize × S → Result (ControlFlow (Range Usize × S) S))
    (inv : ℕ → S → Prop) (stop : Usize)
    (hdone : ∀ r s, r.end = stop → r.start.val = stop.val → inv r.start.val s →
      IteratorRange.next StepUsize r = ok (none, r) → body (r, s) = ok (done s))
    (hstep : ∀ r r' s, r.end = stop → r.start.val < stop.val → inv r.start.val s →
      IteratorRange.next StepUsize r = ok (some r.start, r') →
      ∃ s', body (r,s) = ok (cont (r',s')) ∧ inv (r.start.val+1) s')
    (r : Range Usize) (s : S) (he : r.end = stop) (hle : r.start.val ≤ stop.val)
    (hi : inv r.start.val s) : ∃ s', loop body (r,s) = ok s' ∧ inv stop.val s' := by
  induction hk : stop.val - r.start.val generalizing r s with
  | zero =>
    have hs : r.start.val = stop.val := by omega
    have hn := next_ge r (by rw [he]; omega)
    exact ⟨s, by rw [loop.eq_1, hdone r s he hs hi hn], hs ▸ hi⟩
  | succ k ih =>
    have hlt : r.start.val < stop.val := by omega
    obtain ⟨r', hs', he', hn⟩ := next_lt r (by rw [he]; omega)
    obtain ⟨s', hb, hi'⟩ := hstep r r' s he hlt hi hn
    obtain ⟨v, hv, hi''⟩ := ih r' s' (he'.trans he) (by omega) (hs' ▸ hi') (by omega)
    exact ⟨v, by rw [loop.eq_1, hb]; exact hv, hi''⟩

theorem scalar_chunk_refines [G1Externals] (inputs : Slice (Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine)) (start : Usize)
    (hlen : out.val.length = inputs.val.length) (hfull : start.val + 8 ≤ inputs.val.length) :
    ∃ result, uncompress_in_g1_loop0_loop0 { start := 0#usize, «end» := LANES }
      inputs out start = ok result ∧ ScalarWrites inputs out result start.val (start.val + 8) := by
  unfold uncompress_in_g1_loop0_loop0
  simp only [LANES]
  refine range_runs _ (fun lane s => ScalarWrites inputs out s start.val (start.val + lane))
    8#usize ?_ ?_ _ out rfl (by simp) ?_
  · intro r s he hs hinv hn
    simp [uncompress_in_g1_loop0_loop0.body, hn]
  · intro r r' s he hs hinv hn
    have hr : r.start.val < 8 := by simpa [LANES] using hs
    have hbound : start.val + r.start.val < 2 ^ UScalarTy.Usize.numBits := by
      have := (Slice.len inputs).hBounds
      simp only [Slice.len_val, Slice.length, UScalarTy.numBits] at this ⊢
      omega
    let i : Usize := UScalar.ofNatCore (start.val + r.start.val) hbound
    have hi : i.val = start.val + r.start.val := by simp [i]
    refine ⟨s.set i (G1Externals.uncompress inputs.val[i.val]!), ?_, ?_⟩
    · simp only [uncompress_in_g1_loop0_loop0.body, hn, bind_tc_ok,
        Function.uncurry_apply_pair]
      rw [add_ok _ _ hbound]
      simp only [bind_tc_ok]
      have heq := scalar_index inputs s i (by omega) (by have := hinv.1; omega)
      simpa only [bind_assoc, bind_tc_ok] using congrArg
        (fun x => x >>= fun s => ok (cont (r', s))) heq
    · have h := scalarWrites_step inputs out s start.val i (by omega) (by omega)
        (by simpa [hi] using hinv)
      simpa [hi, Nat.add_assoc] using h
  · simpa using scalarWrites_init inputs out start.val

theorem scalar_tail_refines [G1Externals] (inputs : Slice (Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine)) (start : Usize)
    (hlen : out.val.length = inputs.val.length) (hstart : start.val ≤ inputs.val.length) :
    ∃ result, uncompress_in_g1_loop1 inputs out start = ok result ∧
      ScalarWrites inputs out result start.val inputs.val.length := by
  let initial := start.val
  suffices h : ∀ (s : Slice (Option blst.blst_p1_affine)) (i : Usize),
      initial ≤ i.val → i.val ≤ inputs.val.length → ScalarWrites inputs out s initial i.val →
      ∃ result, uncompress_in_g1_loop1 inputs s i = ok result ∧
        ScalarWrites inputs out result initial inputs.val.length by
    exact h out start (by rfl) hstart (scalarWrites_init inputs out start.val)
  intro s i hlow hhigh hinv
  induction hk : inputs.val.length - i.val generalizing s i with
  | zero =>
    have hi : i.val = inputs.val.length := by omega
    refine ⟨s, ?_, hi ▸ hinv⟩
    rw [uncompress_in_g1_loop1, loop.eq_1]
    simp [uncompress_in_g1_loop1.body, hi]
  | succ k ih =>
    have hi : i.val < inputs.val.length := by omega
    have hb : i.val + (1#usize).val < 2 ^ UScalarTy.Usize.numBits := by
      have := (Slice.len inputs).hBounds
      simp only [Slice.len_val, Slice.length, UScalarTy.numBits] at this ⊢
      simp
      omega
    let next : Usize := UScalar.ofNatCore (i.val + (1#usize).val) hb
    have hn : next.val = i.val + 1 := by simp [next]
    let s' := s.set i (G1Externals.uncompress inputs.val[i.val]!)
    have hs' : ScalarWrites inputs out s' initial next.val := by
      rw [hn]
      exact scalarWrites_step inputs out s initial i (by omega) hlow hinv
    obtain ⟨result, hr, hp⟩ := ih s' next (by omega) (by omega) hs' (by omega)
    refine ⟨result, ?_, hp⟩
    rw [uncompress_in_g1_loop1, loop.eq_1]
    have hbdy : uncompress_in_g1_loop1.body inputs s i = ok (cont (s', next)) := by
      simp only [uncompress_in_g1_loop1.body]
      rw [if_pos (by simpa [Slice.len_val, Slice.length] using hi)]
      have hx := scalar_index inputs s i hi (by have := hinv.1; omega)
      simp only [add_ok _ _ hb, bind_tc_ok]
      simpa only [bind_assoc, bind_tc_ok] using congrArg
        (fun x => x >>= fun s => ok (cont (s, next) :
          ControlFlow (Slice (Option blst.blst_p1_affine) × Usize)
            (Slice (Option blst.blst_p1_affine)))) hx
    simp only [hbdy]
    exact hr

end LeanBlsSimd.UncompressG1
