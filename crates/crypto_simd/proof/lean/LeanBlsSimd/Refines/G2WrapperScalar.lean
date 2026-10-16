import LeanBlsSimd.Refines.DecompressG2

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls core.ops.range core.iter.range

namespace LeanBlsSimd.UncompressG2

def ScalarWrites [BlsExternals] (inputs : Slice (Array U8 96#usize))
    (original result : Slice (Option blst.blst_p2_affine)) (start stop : ℕ) : Prop :=
  result.val.length = original.val.length ∧
    ∀ j, j < original.val.length → result.val[j]! =
      if start ≤ j ∧ j < stop then BlsExternals.uncompressG2 inputs.val[j]! else original.val[j]!

private theorem scalarWrites_init [BlsExternals] (inputs : Slice (Array U8 96#usize))
    (out : Slice (Option blst.blst_p2_affine)) (start : ℕ) :
    ScalarWrites inputs out out start start := by
  simp [ScalarWrites]

private theorem scalarWrites_step [BlsExternals] (inputs : Slice (Array U8 96#usize))
    (original out : Slice (Option blst.blst_p2_affine)) (start : ℕ) (i : Usize)
    (hi : i.val < original.val.length) (hstart : start ≤ i.val)
    (h : ScalarWrites inputs original out start i.val) :
    ScalarWrites inputs original
      (out.set i (BlsExternals.uncompressG2 inputs.val[i.val]!)) start (i.val + 1) := by
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

private theorem scalar_index [BlsExternals] (inputs : Slice (Array U8 96#usize))
    (out : Slice (Option blst.blst_p2_affine)) (i : Usize)
    (hi : i.val < inputs.val.length) (ho : i.val < out.val.length) :
    (do let a ← Slice.index_usize inputs i
        let v ← uncompress_in_g2_blst a
        Slice.update out i v) = ok (out.set i (BlsExternals.uncompressG2 inputs.val[i.val]!)) := by
  simp [Slice.index_usize, hi, uncompress_in_g2_blst,
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

theorem scalar_chunk_refines [BlsExternals] (inputs : Slice (Array U8 96#usize))
    (out : Slice (Option blst.blst_p2_affine)) (start len : Usize)
    (hlen : out.val.length = inputs.val.length) (hfull : start.val + len.val ≤ inputs.val.length) :
    ∃ result, uncompress_in_g2_loop0_loop0 { start := 0#usize, «end» := len }
      inputs out start = ok result ∧ ScalarWrites inputs out result start.val (start.val + len.val) := by
  unfold uncompress_in_g2_loop0_loop0
  refine range_runs _ (fun lane s => ScalarWrites inputs out s start.val (start.val + lane))
    len ?_ ?_ _ out rfl (by simp) ?_
  · intro r s he hs hinv hn
    simp [uncompress_in_g2_loop0_loop0.body, hn]
  · intro r r' s he hs hinv hn
    have hbound : start.val + r.start.val < 2 ^ UScalarTy.Usize.numBits := by
      have := (Slice.len inputs).hBounds
      simp only [Slice.len_val, Slice.length, UScalarTy.numBits] at this ⊢
      omega
    let i : Usize := UScalar.ofNatCore (start.val + r.start.val) hbound
    have hi : i.val = start.val + r.start.val := by simp [i]
    refine ⟨s.set i (BlsExternals.uncompressG2 inputs.val[i.val]!), ?_, ?_⟩
    · simp only [uncompress_in_g2_loop0_loop0.body, hn, bind_tc_ok,
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

theorem scalar_chunk_refines_false [BlsExternals] (inputs : Slice (Array U8 96#usize))
    (out : Slice (Option blst.blst_p2_affine)) (start len : Usize)
    (hlen : out.val.length = inputs.val.length) (hfull : start.val + len.val ≤ inputs.val.length) :
    ∃ result, uncompress_in_g2_loop0_loop1 { start := 0#usize, «end» := len }
      inputs out start = ok result ∧ ScalarWrites inputs out result start.val (start.val + len.val) := by
  exact scalar_chunk_refines inputs out start len hlen hfull

end LeanBlsSimd.UncompressG2
