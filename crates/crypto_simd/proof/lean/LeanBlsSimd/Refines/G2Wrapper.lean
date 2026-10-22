import LeanBlsSimd.Refines.G2WrapperOutput
import LeanBlsSimd.Refines.G2WrapperScalar

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.UncompressG2

open DecompressG2

private theorem step_refines [BlsExternals] (inputs : Slice (Array U8 96#usize))
    (out : Slice (Option blst.blst_p2_affine)) (simd : Bool) (start : Usize)
    (hlen : out.val.length = inputs.val.length) (hlt : start.val < inputs.val.length)
    (halign : start.val % 8 = 0) :
    ∃ next result, next.val = start.val + min 8 (inputs.val.length - start.val) ∧
      uncompress_in_g2_loop0.body inputs out simd start = ok (cont (result, simd, next)) ∧
      result.val.length = out.val.length ∧
      ∀ i, i < inputs.val.length → result.val[i]! =
        if start.val ≤ i ∧ i < next.val then (rawOutput simd inputs)[i]! else out.val[i]! := by
  let rest : Usize := UScalar.ofNatCore (inputs.val.length - start.val)
    (lt_of_le_of_lt (Nat.sub_le _ _) (Slice.len inputs).hBounds)
  let len : Usize := UScalar.ofNatCore (min 8 (inputs.val.length - start.val))
    (lt_of_le_of_lt (min_le_left _ _) (by scalar_tac))
  have hl : len.val = min 8 (inputs.val.length - start.val) := by simp [len]
  have hnextlen : start.val + len.val ≤ inputs.val.length := by omega
  let next : Usize := UScalar.ofNatCore (start.val + len.val)
    (lt_of_le_of_lt hnextlen (Slice.len inputs).hBounds)
  have hn : next.val = start.val + len.val := by simp [next]
  have hsub : Slice.len inputs - start = ok rest := by
    rw [sub_ok _ _ (by simpa using Nat.le_of_lt hlt)]
    rfl
  have hchoose : (if rest < LANES then ok rest else ok LANES) = ok len := by
    split <;> congr 1 <;> apply UScalar.eq_of_val_eq <;> simp_all [rest, LANES]
    omega
  have hadd : start + len = ok next := by
    rw [add_ok _ _ (by have := next.hBounds; simpa [hn] using this)]
  have hlt' : start < Slice.len inputs := by simpa using hlt
  cases simd
  · obtain ⟨result, hr, hrl, hrv⟩ := scalar_chunk_refines_false inputs out start len hlen hnextlen
    refine ⟨next, result, by omega, ?_, hrl, ?_⟩
    · simp only [uncompress_in_g2_loop0.body, hlt', if_true, hsub, bind_tc_ok, hchoose, hr, hadd, Bool.false_eq_true, if_false]
    · intro i hi
      rw [hrv i (by omega)]
      simp only [hn]
      split_ifs
      · exact (rawOutput_scalar false inputs i hi (Or.inl rfl)).symm
      · rfl
  · by_cases hk : 3 ≤ len.val
    · let ss : Slice (Array U8 96#usize) :=
        ⟨inputs.val.slice start.val next.val,
          le_trans (List.slice_length_le _ _ _) inputs.property⟩
      let os : Slice (Option blst.blst_p2_affine) :=
        ⟨out.val.slice start.val next.val, le_trans (List.slice_length_le _ _ _) out.property⟩
      have hss : ss.val.length = len.val := by
        simp only [ss, List.slice_length]
        omega
      have hos : os.val.length = len.val := by
        simp only [os, List.slice_length]
        omega
      obtain ⟨r, hr, hrv⟩ := chunk_slice_refines inputs start next (by omega) halign hlt
        (by omega) ss rfl os (hos.trans hss.symm)
      let result := out.setSlice! start.val r.val
      refine ⟨next, result, by omega, ?_, ?_, ?_⟩
      · have hindex : core.slice.index.Slice.index
            (core.slice.index.SliceIndexRangeUsizeSlice (Array U8 96#usize)) inputs
            { start, «end» := next } = ok ss :=
          slice_index_ok inputs start next (by omega) (by omega)
        have hmut : core.slice.index.Slice.index_mut
            (core.slice.index.SliceIndexRangeUsizeSlice (Option blst.blst_p2_affine)) out
            { start, «end» := next } = ok (os, fun s => out.setSlice! start.val s.val) := by
          simp only [core.slice.index.Slice.index_mut,
            core.slice.index.SliceIndexRangeUsizeSlice.index_mut, UScalar.le_equiv]
          rw [if_pos (by simp only [Slice.length]; constructor <;> omega)]
          rfl
        have hk' : len >= MIN_KERNEL_LANES := by simpa [MIN_KERNEL_LANES] using hk
        simp only [uncompress_in_g2_loop0.body, hlt', if_true, hsub, bind_tc_ok,
          hchoose, hk', hadd, hindex, hmut, Function.uncurry_apply_pair, hr, result]
      · simp [result, Slice.setSlice!]
      · intro i hi
        simp only [result, Slice.setSlice!_val, hrv]
        by_cases h : start.val ≤ i ∧ i < next.val
        · rw [if_pos h, List.getElem!_setSlice!_middle]
          · rw [List.getElem!_slice _ _ _ _ (by simp; omega)]
            congr 1
            omega
          · rw [List.slice_length, rawOutput_length]
            omega
        · rw [if_neg h]
          apply List.getElem!_setSlice!_same
          rw [List.slice_length, rawOutput_length]
          omega
    · obtain ⟨result, hr, hrl, hrv⟩ := scalar_chunk_refines inputs out start len hlen hnextlen
      refine ⟨next, result, by omega, ?_, hrl, ?_⟩
      · have hk' : ¬ len >= MIN_KERNEL_LANES := by simpa [MIN_KERNEL_LANES] using hk
        simp only [uncompress_in_g2_loop0.body, hlt', if_true, hsub, bind_tc_ok,
          hchoose, hk', if_false, hr, hadd]
      · intro i hi
        rw [hrv i (by omega)]
        simp only [hn]
        split_ifs with h
        · apply (rawOutput_scalar true inputs i hi (Or.inr ?_)).symm
          have hidiv : i / 8 * 8 = start.val := by omega
          simp only [chunkLength, List.length_map, hidiv]
          omega
        · rfl

private theorem loop_refines [BlsExternals] (inputs : Slice (Array U8 96#usize))
    (out : Slice (Option blst.blst_p2_affine)) (simd : Bool) (start : Usize)
    (hlen : out.val.length = inputs.val.length) (hle : start.val ≤ inputs.val.length)
    (halign : start.val % 8 = 0 ∨ start.val = inputs.val.length) :
    ∃ result, uncompress_in_g2_loop0 inputs out simd start = ok result ∧
      result.val.length = out.val.length ∧
      ∀ i, i < inputs.val.length → result.val[i]! =
        if start.val ≤ i then (rawOutput simd inputs)[i]! else out.val[i]! := by
  induction hk : inputs.val.length - start.val using Nat.strong_induction_on generalizing start out with
  | h n ih =>
    by_cases heq : start.val = inputs.val.length
    · refine ⟨out, ?_, rfl, ?_⟩
      · rw [uncompress_in_g2_loop0, loop.eq_1]
        simp [uncompress_in_g2_loop0.body, heq]
      · intro i hi
        simp [show ¬ start.val ≤ i by omega]
    · obtain ⟨next, middle, hn, hb, hml, hmv⟩ :=
        step_refines inputs out simd start hlen (by omega) (by omega)
      have hnext : next.val ≤ inputs.val.length := by omega
      have hna : next.val % 8 = 0 ∨ next.val = inputs.val.length := by omega
      obtain ⟨result, hr, hrl, hrv⟩ := ih (inputs.val.length - next.val) (by omega)
        middle next (hml.trans hlen) hnext hna rfl
      refine ⟨result, ?_, hrl.trans hml, ?_⟩
      · unfold uncompress_in_g2_loop0 at *
        rw [loop.eq_1]
        simp only [hb]
        exact hr
      · intro i hi
        rw [hrv i hi, hmv i hi]
        split_ifs <;> first | rfl | omega

theorem uncompress_refines [BlsExternals] (inputs : Slice (Array U8 96#usize))
    (out : Slice (Option blst.blst_p2_affine)) (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g2 inputs out = ok result ∧
      result.val = (uncompress BlsExternals.simdAvailable modelBlst
        (inputs.val.map (ofArray ofU8))).map (Option.map toBlstP2Affine) := by
  obtain ⟨result, hr, hrl, hrv⟩ := loop_refines inputs out BlsExternals.simdAvailable 0#usize
    hlen (by simp) (Or.inl (by simp))
  refine ⟨result, ?_, ?_⟩
  · have heq : Slice.len out = Slice.len inputs := UScalar.eq_of_val_eq (by simpa using hlen)
    simp only [silver_crypto_simd.bls.uncompress_in_g2, heq, massert, ↓reduceIte,
      bind_tc_ok, ifma_available, hr]
  · change result.val = rawOutput BlsExternals.simdAvailable inputs
    apply List.ext_getElem
    · rw [hrl, hlen, rawOutput_length]
    · intro i hi ht
      rw [← getElem!_pos result.val i hi, ← getElem!_pos (rawOutput _ inputs) i ht]
      simpa using hrv i (by simpa using ht)

end LeanBlsSimd.UncompressG2
