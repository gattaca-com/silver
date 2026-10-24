import LeanBlsSimd.Portable.Decode.Correct
import LeanBlsSimd.Portable.G1DecoderContract

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls core.ops.range core.iter.range

namespace LeanBlsSimd.UncompressG1

def ScalarWrites (inputs : Slice (Array U8 48#usize))
    (original result : Slice (Option blst.blst_p1_affine)) (start stop : ℕ) : Prop :=
  result.val.length = original.val.length ∧
    ∀ j, j < original.val.length → result.val[j]! =
      if start ≤ j ∧ j < stop then specVerdict inputs.val[j]! else original.val[j]!

private theorem scalarWrites_init (inputs : Slice (Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine)) (start : ℕ) :
    ScalarWrites inputs out out start start := by
  simp [ScalarWrites]

private theorem scalarWrites_step (inputs : Slice (Array U8 48#usize))
    (original out : Slice (Option blst.blst_p1_affine)) (start : ℕ) (i : Usize)
    (hi : i.val < original.val.length) (hstart : start ≤ i.val)
    (h : ScalarWrites inputs original out start i.val) :
    ScalarWrites inputs original
      (out.set i (specVerdict inputs.val[i.val]!)) start (i.val + 1) := by
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

private theorem scalar_index [RuntimeFeatures]
    (inputs : Slice (Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine)) (i : Usize)
    (hi : i.val < inputs.val.length) (ho : i.val < out.val.length) :
    (do let a ← Slice.index_usize inputs i
        let v ← portable.decompress.uncompress_in_g1 a
        Slice.update out i v) = ok (out.set i (specVerdict inputs.val[i.val]!)) := by
  simp [Slice.index_usize, hi, (LeanBlsSimd.Portable.Decode.g1_decoder_correct).singleton,
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

theorem scalar_chunk_refines [RuntimeFeatures]
    (inputs : Slice (Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine)) (pairs start : Usize)
    (hlen : out.val.length = inputs.val.length)
    (hstart : start.val ≤ pairs.val) (hbound : pairs.val ≤ inputs.val.length)
    (heven : (pairs.val - start.val) % 2 = 0) :
    ∃ result, portable.decompress.uncompress_all_in_g1_loop inputs out pairs start =
      ok (result, pairs) ∧ ScalarWrites inputs out result start.val pairs.val := by
  let initial := start.val
  suffices h : ∀ (s : Slice (Option blst.blst_p1_affine)) (i : Usize),
      initial ≤ i.val → i.val ≤ pairs.val → (pairs.val - i.val) % 2 = 0 →
      ScalarWrites inputs out s initial i.val →
      ∃ result, portable.decompress.uncompress_all_in_g1_loop inputs s pairs i =
        ok (result, pairs) ∧ ScalarWrites inputs out result initial pairs.val by
    exact h out start (by rfl) hstart heven (scalarWrites_init inputs out start.val)
  intro s i hlow hhigh heven hinv
  induction hk : pairs.val - i.val using Nat.strong_induction_on generalizing s i with
  | h n ih =>
    by_cases hi : i.val = pairs.val
    · have hie : i = pairs := UScalar.eq_of_val_eq hi
      subst i
      refine ⟨s, ?_, hinv⟩
      rw [portable.decompress.uncompress_all_in_g1_loop, loop.eq_1]
      simp [portable.decompress.uncompress_all_in_g1_loop.body]
    · have htwo : i.val + 2 ≤ pairs.val := by omega
      have hi0 : i.val < inputs.val.length := by omega
      have hi1 : i.val + 1 < inputs.val.length := by omega
      have hb2 : i.val + 2 < 2 ^ UScalarTy.Usize.numBits :=
        lt_of_le_of_lt (by simpa only [Slice.len_val, Slice.length] using (show i.val + 2 ≤ inputs.val.length by omega)) (Slice.len inputs).hBounds
      let j : Usize := UScalar.ofNatCore (i.val + 1) (by omega)
      let next : Usize := UScalar.ofNatCore (i.val + 2) hb2
      have hj : j.val = i.val + 1 := by simp [j]
      have hn : next.val = i.val + 2 := by simp [next]
      let s1 := s.set i (specVerdict inputs.val[i.val]!)
      let s2 := s1.set j (specVerdict inputs.val[j.val]!)
      have hs1 : ScalarWrites inputs out s1 initial j.val := by
        rw [hj]
        exact scalarWrites_step inputs out s initial i (by omega) hlow hinv
      have hs2 : ScalarWrites inputs out s2 initial next.val := by
        rw [hn, show i.val + 2 = j.val + 1 by omega]
        exact scalarWrites_step inputs out s1 initial j (by omega) (by omega) hs1
      have hbdy : portable.decompress.uncompress_all_in_g1_loop.body inputs pairs s i =
          ok (cont (s2, next)) := by
        have ha1 : i + 1#usize = ok j := by
          rw [add_ok i 1#usize (by simpa using (show i.val + 1 < 2 ^ UScalarTy.Usize.numBits by omega))]
          rfl
        have ha2 : i + 2#usize = ok next := by
          rw [add_ok i 2#usize (by simpa using hb2)]
          rfl
        have hslen := hinv.1
        simp [portable.decompress.uncompress_all_in_g1_loop.body,
          show i < pairs from (by change i.val < pairs.val; omega),
          Slice.index_usize, hi0, hj, hi1, ha1, ha2, (LeanBlsSimd.Portable.Decode.g1_decoder_correct).pair,
          Array.index_usize, Array.make, Slice.update, s2, s1,
          Slice.set, Slice.setAtNat, hslen, hlen]
      obtain ⟨result, hr, hp⟩ := ih (pairs.val - next.val) (by omega)
        s2 next (by omega) (by omega) (by omega) hs2 rfl
      refine ⟨result, ?_, hp⟩
      rw [portable.decompress.uncompress_all_in_g1_loop, loop.eq_1]
      simp only [hbdy]
      exact hr

theorem scalar_tail_refines [RuntimeFeatures]
    (inputs : Slice (Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, portable.decompress.uncompress_all_in_g1 inputs out = ok result ∧
      result.val = inputs.val.map specVerdict := by
  let n := Slice.len inputs
  let q : Usize := UScalar.ofNatCore (n.val / 2)
    (lt_of_le_of_lt (Nat.div_le_self _ _) n.hBounds)
  have hb : n.val / 2 * 2 < 2 ^ UScalarTy.Usize.numBits :=
    lt_of_le_of_lt (Nat.div_mul_le_self _ _) n.hBounds
  let pairs : Usize := UScalar.ofNatCore (n.val / 2 * 2) hb
  have hp : pairs.val = inputs.val.length / 2 * 2 := by simp [pairs, n]
  obtain ⟨middle, hm, hmv⟩ := scalar_chunk_refines inputs out pairs 0#usize hlen
    (by simp) (by omega) (by simp [hp])
  have heq : Slice.len out = Slice.len inputs := UScalar.eq_of_val_eq (by simpa using hlen)
  have hd : n / 2#usize = ok q := by
    rw [div_ok n 2#usize (by decide)]
    rfl
  have hmul : q * 2#usize = ok pairs := by
    rw [mul_ok q 2#usize (by simpa [q] using hb)]
    rfl
  have finish (result : Slice (Option blst.blst_p1_affine))
      (hv : ScalarWrites inputs out result 0 inputs.val.length) :
      result.val = inputs.val.map specVerdict := by
    apply List.ext_getElem (by simp [hv.1, hlen])
    intro i hi hj
    have hin : i < inputs.val.length := by simpa using hj
    have h := hv.2 i (by omega)
    simpa [hin, getElem!_pos, List.getElem_map, show i < result.val.length by omega] using h
  by_cases hodd : pairs.val < inputs.val.length
  · have hn : pairs.val + 1 = inputs.val.length := by omega
    let result := middle.set pairs (specVerdict inputs.val[pairs.val]!)
    have hv : ScalarWrites inputs out result 0 inputs.val.length := by
      rw [← hn]
      exact scalarWrites_step inputs out middle 0 pairs (by omega) (by omega) hmv
    refine ⟨result, ?_, finish result hv⟩
    simp only [portable.decompress.uncompress_all_in_g1, heq, massert, ↓reduceIte,
      bind_tc_ok, show Slice.len inputs = n from rfl, hd, hmul, hm,
      Function.uncurry_apply_pair]
    rw [if_pos (by simpa [n] using hodd)]
    exact scalar_index inputs middle pairs hodd (by have := hmv.1; omega)
  · have hn : pairs.val = inputs.val.length := by omega
    refine ⟨middle, ?_, finish middle (hn ▸ hmv)⟩
    simp [portable.decompress.uncompress_all_in_g1, heq, massert,
      show Slice.len inputs = n from rfl, hd, hmul, hm, hodd, n]

end LeanBlsSimd.UncompressG1
