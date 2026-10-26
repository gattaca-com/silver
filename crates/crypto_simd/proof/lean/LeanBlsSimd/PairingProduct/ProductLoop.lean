import LeanBlsSimd.PairingProduct.FieldRep
import LeanBlsSimd.PairingProduct.Owner

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.PairingProduct.ProductLoop

noncomputable section

def factorProduct (pairs : List pairing_product.AffinePair) : Fp12Field :=
  (pairs.map fun p => Fp12.toField (pairingFactor (Kzg.g1ReadAffine p.p, Kzg.g2ReadAffine p.q))).prod

def SingleSetCorrect : Prop :=
  ∀ (s : Slice pairing_product.AffinePair), 1 ≤ s.val.length → s.val.length ≤ 8 →
    (∀ p ∈ s.val, Kzg.G1AffineValid p.p ∧ Kzg.G2AffineValid p.q) →
    (∀ p ∈ s.val, finitePair p = true) →
    ∃ result, (do let lp ← lane_pairs.LanePairs.new s; lane_pairs.LanePairs.miller_loop lp) = ok result ∧
      ∃ value, FieldRep result.value value ∧
        (result.degenerate = 0#u8 → value ^ finalExpExponent = factorProduct s.val ^ finalExpExponent)

theorem pairingCheck_eq (s : Slice pairing_product.AffinePair) :
    pairingCheck (specPairs s) = decide (factorProduct s.val ^ finalExpExponent = 1) := by
  apply Bool.eq_iff_iff.mpr
  rw [SpecPairing.pairingCheck_eq, Fp12.isOne_iff, toField_finalExponentiation, toField_pairingFold]
  simp only [specPairs, List.toList_toArray, List.map_map, Function.comp_def,
    factorProduct, decide_eq_true_eq]

private theorem or_zero_iff (a b : U8) :
    (a ||| b) = 0#u8 ↔ a = 0#u8 ∧ b = 0#u8 := by
  rw [UScalar.eq_equiv_bv_eq (a ||| b) 0#u8, UScalar.eq_equiv_bv_eq a 0#u8,
    UScalar.eq_equiv_bv_eq b 0#u8]
  exact BitVec.or_eq_zero_iff

private theorem factorProduct_split (pairs : List pairing_product.AffinePair) (start count : Nat) :
    factorProduct (pairs.drop start) =
      factorProduct (pairs.slice start (start + count)) * factorProduct (pairs.drop (start + count)) := by
  unfold factorProduct
  rw [← List.prod_append, ← List.map_append]
  congr 1
  simp only [List.slice, Nat.add_sub_cancel_left, ← List.drop_drop]
  exact congrArg (List.map _) (List.take_append_drop count (pairs.drop start)).symm

private def chunk (s : Slice pairing_product.AffinePair) (start count : Nat) :
    Slice pairing_product.AffinePair :=
  ⟨s.val.slice start (start + count), by
    have := s.property
    simp only [List.slice, List.length_take, List.length_drop]
    omega⟩

private theorem chunk_index (s : Slice pairing_product.AffinePair) (start stop : Usize)
    (hstart : start.val ≤ stop.val) (hstop : stop.val ≤ s.val.length) :
    core.slice.index.Slice.index
      (core.slice.index.SliceIndexRangeUsizeSlice pairing_product.AffinePair)
      s { start, «end» := stop } = ok (chunk s start.val (stop.val - start.val)) := by
  simp [core.slice.index.Slice.index, core.slice.index.SliceIndexRangeUsizeSlice.index,
    chunk, hstart, hstop, UScalar.le_equiv, Slice.length]

private theorem slice_length_lt (s : Slice pairing_product.AffinePair) :
    s.val.length < 2 ^ UScalarTy.Usize.numBits := by
  have h := s.property
  have := two_pow_32_le_usize
  simp only [Usize.max_def, Usize.numBits_def] at h
  omega

theorem lane_loop_refines (sets : SingleSetCorrect)
    (s : Slice pairing_product.AffinePair)
    (valid : ∀ p ∈ s.val, Kzg.G1AffineValid p.p ∧ Kzg.G2AffineValid p.q)
    (finite : ∀ p ∈ s.val, finitePair p = true)
    (start : Usize) (hstart : start.val ≤ s.val.length)
    (product : fp12.Fp12) (degenerate : U8) (value : Fp12Field) (rep : FieldRep product value) :
    ∃ out flags result,
      pairing_product.PairingInputs.lane_is_one_loop s product degenerate start = ok (out, flags) ∧
      FieldRep out result ∧
      (flags = 0#u8 → degenerate = 0#u8 ∧
        result ^ finalExpExponent = (value * factorProduct (s.val.drop start.val)) ^ finalExpExponent) := by
  induction hn : s.val.length - start.val using Nat.strong_induction_on
      generalizing start product degenerate value with
  | h remaining ih =>
    by_cases hlt : start.val < s.val.length
    · let count := min (s.val.length - start.val) 8
      have hcount : 1 ≤ count ∧ count ≤ 8 ∧ start.val + count ≤ s.val.length := by
        dsimp [count]
        omega
      let countU : Usize := UScalar.ofNatCore count
        (by have := two_pow_32_le_usize; omega)
      let next : Usize := UScalar.ofNatCore (start.val + count)
        (by have := slice_length_lt s; omega)
      have hnext : next.val = start.val + count := rfl
      have hsize : (chunk s start.val count).val.length = count := by
        simp [chunk, List.slice]
        omega
      have hmem : ∀ p ∈ (chunk s start.val count).val, p ∈ s.val := by
        intro p hp
        exact List.mem_of_mem_drop (List.mem_of_mem_take hp)
      obtain ⟨setResult, hset, setValue, setRep, setPower⟩ := sets (chunk s start.val count)
        (by omega) (by omega) (fun p hp => valid p (hmem p hp)) (fun p hp => finite p (hmem p hp))
      obtain ⟨lp, hlp, hmiller⟩ : ∃ lp,
          lane_pairs.LanePairs.new (chunk s start.val count) = ok lp ∧
          lane_pairs.LanePairs.miller_loop lp = ok setResult := by
        cases he : lane_pairs.LanePairs.new (chunk s start.val count) with
        | ok lp => exact ⟨lp, rfl, by simpa only [he, bind_tc_ok] using hset⟩
        | fail e => simp [he] at hset
        | div => simp [he] at hset
      obtain ⟨product', hmul, rep'⟩ := FieldRep.mul rep setRep
      have hbody : pairing_product.PairingInputs.lane_is_one_loop.body s product degenerate start =
          ok (cont (product', degenerate ||| setResult.degenerate, next)) := by
        simp only [pairing_product.PairingInputs.lane_is_one_loop.body, UScalar.lt_equiv,
          Slice.len, Usize.ofNatCore_val_eq, hlt, if_true]
        rw [sub_ok _ _ hstart]
        simp only [bind_tc_ok]
        have hlen : (if s.val.length - start.val < 8 then
            ok (UScalar.ofNatCore (s.val.length - start.val)
              (by have := slice_length_lt s; omega)) else ok limbs.LANES) = ok countU := by
          split <;> apply congrArg ok <;> apply UScalar.eq_of_val_eq <;>
            simp [countU, count, limbs.LANES] <;> omega
        simp only [UScalar.ofNatCore_val_eq, Usize.ofNatCore_val_eq, limbs.LANES] at hlen ⊢
        rw [hlen]
        simp only [bind_tc_ok]
        rw [add_ok _ _ (by change start.val + count < _; have := slice_length_lt s; omega)]
        change (do
          let part ← core.slice.index.Slice.index
            (core.slice.index.SliceIndexRangeUsizeSlice pairing_product.AffinePair)
            s { start, «end» := next }
          let lp ← lane_pairs.LanePairs.new part
          let result ← lane_pairs.LanePairs.miller_loop lp
          let product1 ← fp12.Fp12.mul product result.value
          let flags ← lift (degenerate ||| result.degenerate)
          ok (cont (product1, flags, next))) = _
        rw [chunk_index s start next (by omega) (by omega)]
        have he : next.val - start.val = count := by omega
        simp only [he, bind_tc_ok, hlp, hmiller, hmul, lift]
      obtain ⟨out, flags, result, hloop, hout, hpower⟩ :=
        ih (s.val.length - next.val) (by omega) next (by omega) product'
          (degenerate ||| setResult.degenerate) (value * setValue) rep' rfl
      refine ⟨out, flags, result, ?_, hout, ?_⟩
      · unfold pairing_product.PairingInputs.lane_is_one_loop
        rw [loop.eq_1]
        simp only [hbody]
        exact hloop
      · intro hz
        obtain ⟨hflags, he⟩ := hpower hz
        obtain ⟨hdeg, hsetdeg⟩ := or_zero_iff _ _ |>.mp hflags
        refine ⟨hdeg, ?_⟩
        rw [he, factorProduct_split s.val start.val count, hnext]
        simp only [mul_pow, mul_assoc, setPower hsetdeg]
        rfl
    · have hs : start.val = s.val.length := by omega
      refine ⟨product, degenerate, value, ?_, rep, ?_⟩
      · unfold pairing_product.PairingInputs.lane_is_one_loop
        rw [loop.eq_1]
        simp only [pairing_product.PairingInputs.lane_is_one_loop.body, UScalar.lt_equiv,
          Slice.len, Usize.ofNatCore_val_eq, hlt, if_false]
      · intro hz
        refine ⟨hz, ?_⟩
        simp [hs, factorProduct]

theorem lane_is_one_refines [PairingExternals] (sets : SingleSetCorrect)
    (blst : BlstMatchesSpec) (inputs : pairing_product.PairingInputs)
    (valid : ∀ p ∈ inputs.pairs.val, Kzg.G1AffineValid p.p ∧ Kzg.G2AffineValid p.q)
    (finite : ∀ p ∈ inputs.pairs.val, finitePair p = true) :
    pairing_product.PairingInputs.lane_is_one inputs = ok (pairingCheck (specPairs inputs.pairs)) := by
  obtain ⟨one, hone, hrep⟩ := FieldRep.one
  obtain ⟨out, flags, value, hloop, rep, hpower⟩ := lane_loop_refines sets inputs.pairs valid finite
    0#usize (by simp) one 0#u8 1 hrep
  simp only [pairing_product.PairingInputs.lane_is_one, hone, bind_tc_ok, hloop,
    Function.uncurry_apply_pair]
  by_cases hz : flags = 0#u8
  · simp only [hz, bne_self_eq_false, Bool.false_eq_true, if_false]
    rw [FieldRep.final_verdict rep, pairingCheck_eq]
    have he := (hpower hz).2
    simpa using congrArg (fun x : Fp12Field => ok (decide (x = 1))) he
  · simp only [bne_iff_ne]
    rw [if_pos hz]
    exact blst_is_one_eq_spec blst inputs valid
      (fun p hp => by simpa [finitePair] using finite p hp)

theorem check_refines [RuntimeFeatures] [PairingExternals] (sets : SingleSetCorrect)
    (blst : BlstMatchesSpec) (inputs : pairing_product.PairingInputs)
    (valid : ∀ p ∈ inputs.pairs.val, Kzg.G1AffineValid p.p ∧ Kzg.G2AffineValid p.q)
    (finite : ∀ p ∈ inputs.pairs.val, finitePair p = true) :
    pairing_product.PairingInputs.check inputs = ok (pairingCheck (specPairs inputs.pairs)) := by
  by_cases hempty : inputs.pairs.val = []
  · simp [pairing_product.PairingInputs.check, core.slice.Slice.is_empty, Slice.length,
      hempty, specPairs, pairingCheck_empty]
  · have hlen : inputs.pairs.val.length ≠ 0 := by simpa using hempty
    simp only [pairing_product.PairingInputs.check, core.slice.Slice.is_empty,
      Slice.length, hlen, decide_false, bind_tc_ok, Bool.false_eq_true, if_false, ifma_available]
    split
    · exact lane_is_one_refines sets blst inputs valid finite
    · exact blst_is_one_eq_spec blst inputs valid
        (fun p hp => by simpa [finitePair] using finite p hp)

end

end LeanBlsSimd.PairingProduct.ProductLoop
