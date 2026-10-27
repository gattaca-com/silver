import LeanBlsSimd.Refines.G1Blst
import LeanBlsSimd.Portable.Decode.Correct
import LeanBlsSimd.Refines.DecompressG1
import LeanBlsSimd.Refines.G1WrapperModel
import LeanBlsSimd.Proofs.Mmask8
import LeanBlsSimd.Refines.G1WrapperScalar
import LeanBlsSimd.Refines.G1WrapperSimd

open LeanBlsSimd.Portable.Decode (g1_decoder_correct)

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd

namespace UncompressG1

open DecompressG1

def modelBlst (bytes : Encoding) : Option BlstP1Affine :=
  (specVerdict (toArray toU8 bytes)).map ofBlstP1Affine

private theorem mask_bit (m : UInt8) (l : Fin 8) :
    (toU8 m &&& toU8 (1 <<< l.val.toUInt8) != 0#u8) = m.toNat.testBit l := by
  rw [Bool.eq_iff_iff]
  simp only [bne_iff_ne, toU8_and]
  change (toU8 (m &&& (1 <<< l.val.toUInt8)) ≠ toU8 0 ↔ _)
  simp only [ne_eq, toU8_inj]
  exact Mmask8.and_one_shiftLeft_ne_zero m l

private def vectorSlice {α : Type} {n : ℕ} (v : Vector α n) (h : n ≤ Usize.max) : Slice α :=
  ⟨v.toList, by simpa using h⟩

private theorem slice_update_ok {α : Type} (s : Slice α) (i : Usize) (x : α)
    (h : i.val < s.val.length) : Slice.update s i x = ok (s.set i x) := by
  simp [Slice.update, h, Slice.set, Slice.setAtNat]

private theorem vectorSlice_set {α : Type} {n : ℕ} (v : Vector α n) (h : n ≤ Usize.max)
    (i : Usize) (hi : i.val < n) (x : α) :
    (vectorSlice v h).set i x = vectorSlice (v.set i.val x hi) h := by
  apply Subtype.ext
  simp [vectorSlice, Slice.set, Slice.setAtNat, Vector.toList_set]

private theorem modelBlst_roundtrip [RuntimeFeatures] (a : Array U8 48#usize) :
    (modelBlst (ofArray ofU8 a)).map toBlstP1Affine = specVerdict a := by
  simp [modelBlst, toArray_ofArray, Option.map_map, Function.comp_def]

theorem chunk_refines [RuntimeFeatures] (inputs : Array (Array U8 48#usize) 8#usize)
    (out : Slice (Option blst.blst_p1_affine)) (hlen : out.val.length = 8) :
    ∃ result, silver_crypto_simd.bls.decompress_g1_chunk inputs out = ok result ∧
      result.val = ((chunk modelBlst (ofArray (ofArray ofU8) inputs)).toList.map
        (Option.map toBlstP1Affine)) := by
  let b := decompress (ofArray (ofArray ofU8) inputs)
  let target := (chunk modelBlst (ofArray (ofArray ofU8) inputs)).map (Option.map toBlstP1Affine)
  have hb : 8 ≤ Usize.max := by scalar_tac
  let enc := fun v : Vector (Option blst.blst_p1_affine) 8 => vectorSlice v hb
  have ho : enc (ofSlice id out hlen) = out := by
    apply Subtype.ext
    simp [enc, vectorSlice]
  refine ⟨enc target, ?_, by simp [enc, vectorSlice, target, Vector.toList_map]⟩
  rw [silver_crypto_simd.bls.decompress_g1_chunk, decompress_refines]
  simp only [bind_tc_ok, decompress_g1_chunk_loop]
  rw [← ho]
  apply loop_range (n := 8) _ LANES (by simp [LANES]) enc
    (fun v j => v.set j (target[j])) enc (ofSlice id out hlen) (enc target)
  · intro r v he hs hn
    simp only [decompress_g1_chunk_loop.body, hn, bind_tc_ok, Function.uncurry_apply_pair]
  · intro r r' v j he hs he' hs' hn
    have hj : r.start.val < 8 := by omega
    simp only [decompress_g1_chunk_loop.body, hn, bind_tc_ok, Function.uncurry_apply_pair]
    rw [toU8_shiftLeft_one _ hj]
    simp only [lift, bind_tc_ok, toBatch]
    rw [show r.start.val = j.val from hs, mask_bit]
    have ht : target[j] =
        if b.undecided.toNat.testBit j then specVerdict (inputs.val[j.val]'(by simp [inputs.property]))
        else if b.valid.toNat.testBit j then some (toBlstP1Affine b.points[j]) else none := by
      simp only [target, chunk, Fin.getElem_fin, Vector.getElem_map, Vector.getElem_ofFn, laneVerdict]
      split
      · simp only [getElem_ofArray, modelBlst_roundtrip]
      · split <;> rfl
    cases hu : b.undecided.toNat.testBit j
    · simp only [Bool.false_eq_true, ↓reduceIte]
      rw [mask_bit]
      cases hv : b.valid.toNat.testBit j
      · simp only [Bool.false_eq_true, ↓reduceIte, bind_tc_ok, Function.uncurry_apply_pair]
        rw [slice_update_ok _ _ _ (by simp [enc, vectorSlice, hs]), vectorSlice_set v hb r.start hj]
        simp only [bind_tc_ok, enc, ht, hu, hv, hs, Bool.false_eq_true, ↓reduceIte]
      · simp only [↓reduceIte]
        rw [index_usize_toArray _ _ _ _ hj]
        simp only [bind_tc_ok, Function.uncurry_apply_pair]
        rw [slice_update_ok _ _ _ (by simp [enc, vectorSlice, hs]), vectorSlice_set v hb r.start hj]
        simp only [bind_tc_ok, enc, ht, hu, hv, hs, Bool.false_eq_true, ↓reduceIte]
        rfl
    · simp only [↓reduceIte]
      rw [index_usize_eq _ _ hj]
      simp only [g1_decoder_correct.singleton, bind_tc_ok, Function.uncurry_apply_pair]
      rw [slice_update_ok _ _ _ (by simp [enc, vectorSlice, hs]), vectorSlice_set v hb r.start hj]
      simp only [bind_tc_ok, enc, ht, hu, hs, ↓reduceIte]
  · rw [foldl_set_ofFn]
    congr 1
    ext i hi
    simp

private def rawOutput [RuntimeFeatures] (simd : Bool) (inputs : Slice (Array U8 48#usize)) :=
  (uncompress simd modelBlst (inputs.val.map (ofArray ofU8))).map (Option.map toBlstP1Affine)

private theorem rawOutput_length [RuntimeFeatures] (simd : Bool) (inputs : Slice (Array U8 48#usize)) :
    (rawOutput simd inputs).length = inputs.val.length := by
  simp [rawOutput]

private theorem rawOutput_scalar [RuntimeFeatures] (simd : Bool) (inputs : Slice (Array U8 48#usize))
    (i : ℕ) (hi : i < inputs.val.length)
    (hscalar : simd = false ∨ inputs.val.length / 8 * 8 ≤ i) :
    (rawOutput simd inputs)[i]! = specVerdict inputs.val[i]! := by
  rw [getElem!_pos _ _ (by simpa [rawOutput] using hi)]
  simp only [rawOutput, List.getElem_map]
  rw [getElem_uncompress_scalar _ _ _ _ (by simpa using hi) (by simpa using hscalar)]
  rw [getElem!_pos _ _ (by simpa using hi), List.getElem_map, modelBlst_roundtrip]
  rw [getElem!_pos inputs.val i hi]

private theorem chunk_slice_refines [RuntimeFeatures]  (inputs : Slice (Array U8 48#usize))
    (start next : Usize) (hnext : next.val = start.val + 8)
    (halign : start.val % 8 = 0) (hbound : next.val ≤ inputs.val.length)
    (c : Array (Array U8 48#usize) 8#usize)
    (hc : c.val = inputs.val.slice start.val next.val)
    (out : Slice (Option blst.blst_p1_affine)) (hlen : out.val.length = 8) :
    ∃ result, decompress_g1_chunk c out = ok result ∧
      result.val = (rawOutput true inputs).slice start.val next.val := by
  obtain ⟨result, hr, hv⟩ := chunk_refines c out hlen
  refine ⟨result, hr, hv.trans ?_⟩
  have hcmodel : ofArray (ofArray ofU8) c = chunkAt (inputs.val.map (ofArray ofU8)) start.val := by
    apply Vector.ext
    intro lane hlane
    rw [getElem_ofArray, chunkAt_getElem _ _ halign ⟨lane, hlane⟩]
    have hget : c.val[lane]'(by simpa [c.property] using hlane) = inputs.val[start.val + lane]'(by omega) := by
      rw [← getElem!_pos c.val lane (by simpa [c.property] using hlane)]
      rw [hc, List.getElem!_slice _ _ _ _ (by omega), getElem!_pos _ _ (by omega)]
    rw [hget, getElem!_pos _ _ (by simp; omega), List.getElem_map]
  rw [hcmodel]
  apply List.ext_getElem
  · simp only [List.length_map, Vector.length_toList, List.slice_length, rawOutput_length]
    omega
  · intro lane hl hr
    have hlane : lane < 8 := by simpa using hl
    have hi : start.val + lane < inputs.val.length := by omega
    rw [← getElem!_pos ((rawOutput true inputs).slice start.val next.val) lane hr, List.getElem!_slice _ _ _ _ (by rw [rawOutput_length]; omega)]
    rw [getElem!_pos _ _ (by rw [rawOutput_length]; omega)]
    simp only [List.getElem_map, Vector.getElem_toList, rawOutput]
    rw [getElem_uncompress_chunk _ _ _ halign (by simp; omega) ⟨lane, hlane⟩]

private theorem stop_loop_of_step [RuntimeFeatures]
    (inputs : Slice (Array U8 48#usize)) (stop : Usize)
    (target : List (Option blst.blst_p1_affine))
    (halign : stop.val % 8 = 0)
    (hstep : ∀ (start : Usize) (out : Slice (Option blst.blst_p1_affine)),
      start.val < stop.val → start.val % 8 = 0 → out.val.length = inputs.val.length →
      ∃ next out', next.val = start.val + 8 ∧
        uncompress_in_g1_loop.body inputs stop out start = ok (cont (out', next)) ∧
        out'.val.length = out.val.length ∧
        ∀ i, i < inputs.val.length → out'.val[i]! =
          if start.val ≤ i ∧ i < next.val then target[i]! else out.val[i]!)
    (start : Usize) (out : Slice (Option blst.blst_p1_affine))
    (hle : start.val ≤ stop.val) (hs : start.val % 8 = 0)
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, uncompress_in_g1_loop inputs out stop start = ok result ∧
      result.val.length = out.val.length ∧
      ∀ i, i < inputs.val.length → result.val[i]! =
        if start.val ≤ i ∧ i < stop.val then target[i]! else out.val[i]! := by
  induction hk : stop.val - start.val using Nat.strong_induction_on generalizing start out with
  | h n ih =>
   by_cases hz : stop.val = start.val
   ·
    have he : start = stop := UScalar.eq_of_val_eq (by omega)
    subst start
    refine ⟨out, ?_, rfl, ?_⟩
    · unfold uncompress_in_g1_loop
      rw [loop.eq_1]
      simp [uncompress_in_g1_loop.body]
    · intro i hi
      simp only [show ¬(stop.val ≤ i ∧ i < stop.val) by omega, ↓reduceIte]
   ·
    have hlt : start.val < stop.val := by omega
    obtain ⟨next, out', hn, hb, hl, hv⟩ := hstep start out hlt hs hlen
    have hnle : next.val ≤ stop.val := by omega
    have hna : next.val % 8 = 0 := by omega
    obtain ⟨result, hr, hrl, hrv⟩ := ih (stop.val - next.val) (by omega) next out' hnle hna (hl.trans hlen) rfl
    refine ⟨result, ?_, hrl.trans hl, ?_⟩
    · unfold uncompress_in_g1_loop at *
      rw [loop.eq_1]
      simp only [hb]
      exact hr
    · intro i hi
      rw [hrv i hi, hv i hi]
      split_ifs <;> first | rfl | omega

theorem uncompress_refines [RuntimeFeatures] [KzgExternals] [FallbackCorrect]
    (inputs : Slice (Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine)) (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g1 inputs out = ok result ∧
      result.val = (uncompress RuntimeFeatures.simdAvailable modelBlst
        (inputs.val.map (ofArray ofU8))).map (Option.map toBlstP1Affine) := by
  have heq : Slice.len out = Slice.len inputs := UScalar.eq_of_val_eq (by simpa using hlen)
  cases hcpu : RuntimeFeatures.simdAvailable with
  | false =>
    obtain ⟨result, hr, hv⟩ := blst_list_refines inputs out hlen
    have hspec : KzgExternals.uncompressG1 = specVerdict :=
      funext (FallbackCorrect.matchesSpec hcpu)
    refine ⟨result, ?_, ?_⟩
    · simpa [silver_crypto_simd.bls.uncompress_in_g1, heq, ifma_available, hcpu] using hr
    · rw [hv, hspec]
      apply List.ext_getElem (by simp)
      intro i hi hj
      have hin : i < inputs.val.length := by simpa using hi
      have h := rawOutput_scalar false inputs i hin (Or.inl rfl)
      simpa [rawOutput, getElem!_pos, hin] using h.symm
  | true =>
    let n := Slice.len inputs
    let q : Usize := UScalar.ofNatCore (n.val / 8)
      (lt_of_le_of_lt (Nat.div_le_self _ _) n.hBounds)
    have hstopbound : n.val / 8 * 8 < 2 ^ UScalarTy.Usize.numBits :=
      lt_of_le_of_lt (Nat.div_mul_le_self _ _) n.hBounds
    let stop : Usize := UScalar.ofNatCore (n.val / 8 * 8) hstopbound
    have hstop : stop.val = inputs.val.length / 8 * 8 := by simp [stop, n]
    have hstoplen : stop.val ≤ inputs.val.length := by omega
    have hstep : ∀ (start : Usize) (out : Slice (Option blst.blst_p1_affine)),
        start.val < stop.val → start.val % 8 = 0 → out.val.length = inputs.val.length →
        ∃ next out', next.val = start.val + 8 ∧
          uncompress_in_g1_loop.body inputs stop out start = ok (cont (out', next)) ∧
          out'.val.length = out.val.length ∧
          ∀ i, i < inputs.val.length → out'.val[i]! =
            if start.val ≤ i ∧ i < next.val then (rawOutput true inputs)[i]! else out.val[i]! := by
      intro start out hlt halign hlen
      have hnextlen : start.val + 8 ≤ inputs.val.length := by omega
      have hnextbound : start.val + 8 < 2 ^ UScalarTy.Usize.numBits :=
        lt_of_le_of_lt hnextlen (Slice.len inputs).hBounds
      let next : Usize := UScalar.ofNatCore (start.val + 8) hnextbound
      have hn : next.val = start.val + 8 := by simp [next]
      obtain ⟨result, hr, hl, hv⟩ := simd_body_runs inputs out stop start next
        (rawOutput true inputs) hlen (rawOutput_length _ _) hlt hn (by omega)
        (fun c s hc hs => chunk_slice_refines inputs start next hn halign (by omega) c hc s hs)
      exact ⟨next, result, hn, hr, hl, fun i hi => hv i (by omega)⟩
    obtain ⟨middle, hm, hml, hmv⟩ := stop_loop_of_step inputs stop (rawOutput true inputs)
      (by omega) hstep 0#usize out (by simp) (by simp) hlen
    let ss : Slice (Array U8 48#usize) :=
      ⟨inputs.val.slice stop.val n.val, le_trans (List.slice_length_le _ _ _) inputs.property⟩
    let os : Slice (Option blst.blst_p1_affine) :=
      ⟨middle.val.slice stop.val n.val, le_trans (List.slice_length_le _ _ _) middle.property⟩
    have htail : os.val.length = ss.val.length := by
      simp [os, ss, List.slice_length, hml, hlen]
    obtain ⟨tail, ht, htv⟩ := scalar_tail_refines ss os htail
    let result := middle.setSlice! stop.val tail.val
    refine ⟨result, ?_, ?_⟩
    · have hd : n / LANES = ok q := by
        rw [LANES, div_ok n 8#usize (by decide)]
        rfl
      have hmul : q * LANES = ok stop := by
        rw [LANES, mul_ok q 8#usize (by simpa [q] using hstopbound)]
        rfl
      have hindex := slice_index_ok inputs stop n (by simpa [n] using hstoplen) (by simp [n])
      have hmut : core.slice.index.Slice.index_mut
          (core.slice.index.SliceIndexRangeUsizeSlice (Option blst.blst_p1_affine)) middle
          { start := stop, «end» := n } =
          ok (os, fun s => middle.setSlice! stop.val s.val) := by
        simp only [core.slice.index.Slice.index_mut,
          core.slice.index.SliceIndexRangeUsizeSlice.index_mut, UScalar.le_equiv]
        rw [if_pos (by simp only [Slice.length]; constructor <;> simp [n] <;> omega)]
        rfl
      simp only [silver_crypto_simd.bls.uncompress_in_g1, heq, massert, ↓reduceIte,
        bind_tc_ok, ifma_available, hcpu, show Slice.len inputs = n from rfl,
        hd, hmul, hm, hindex, hmut, Function.uncurry_apply_pair]
      change (do let tail ← portable.decompress.uncompress_all_in_g1 ss os
                 ok (middle.setSlice! stop.val tail.val)) = ok result
      rw [ht]
      rfl
    · change result.val = rawOutput true inputs
      apply List.ext_getElem
      · simp [result, Slice.setSlice!, hml, hlen, rawOutput_length]
      · intro i hi hj
        have hin : i < inputs.val.length := by simpa [rawOutput_length] using hj
        rw [← getElem!_pos result.val i hi, ← getElem!_pos (rawOutput true inputs) i hj]
        simp only [result, Slice.setSlice!_val]
        by_cases hprefix : i < stop.val
        · rw [List.getElem!_setSlice!_same _ _ _ _ (by omega), hmv i hin]
          simp [hprefix]
        · have htaillen : tail.val.length = inputs.val.length - stop.val := by
            simp [htv, ss, List.slice_length, n]
          rw [List.getElem!_setSlice!_middle _ _ _ _ (by omega), htv]
          have hidx : i - stop.val < ss.val.length := by
            simp [ss, List.slice_length, n]
            omega
          rw [getElem!_pos _ _ (by simpa using hidx), List.getElem_map]
          change specVerdict ss.val[i - stop.val] = _
          rw [← getElem!_pos ss.val (i - stop.val) hidx]
          change specVerdict ((inputs.val.slice stop.val n.val)[i-stop.val]!) = _
          rw [List.getElem!_slice _ _ _ _ (by simp [n]; omega)]
          have hadd : stop.val + (i - stop.val) = i := by omega
          rw [hadd]
          exact (rawOutput_scalar true inputs i hin (Or.inr (by omega))).symm

end UncompressG1
end LeanBlsSimd
