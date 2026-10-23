import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Bytes
import LeanBlsSimd.Refines.DecompressG2

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel.BytePacking

def wordBytes (w : UInt64) : List U8 := (core.num.U64.to_be_bytes (toU64 w)).val

@[simp] theorem wordBytes_length (w : UInt64) : (wordBytes w).length = 8 :=
  (core.num.U64.to_be_bytes (toU64 w)).property

private theorem from_to_be_bytes (w : U64) :
    core.num.U64.from_be_bytes (core.num.U64.to_be_bytes w) = w := by
  have hm : (core.num.U64.to_be_bytes w).val.map U8.bv = w.bv.toBEBytes := by
    change (w.bv.toBEBytes.map (@UScalar.mk .U8)).map U8.bv = _
    simp only [List.map_map, Function.comp_def, U8.bv]
    exact List.map_id _
  apply UScalar.eq_of_val_eq
  change (BitVec.fromBEBytes ((core.num.U64.to_be_bytes w).val.map U8.bv)).toNat = w.bv.toNat
  rw [hm]
  change (BitVec.fromLEBytes w.bv.toLEBytes.reverse.reverse).toNat = w.bv.toNat
  calc
    _ = (BitVec.fromLEBytes w.bv.toLEBytes).toNat :=
      congrArg (fun xs => (BitVec.fromLEBytes xs).toNat) (List.reverse_reverse _)
    _ = w.bv.toNat := by
      rw [BitVec.fromLEBytes_toLEBytes (show 64 % 8 = 0 by decide)]
      rfl

theorem wordBytes_value (w : UInt64) : bytesVal ((wordBytes w).map ofU8) = w.toNat := by
  have h := DecompressG2.from_be_bytes_refines (core.num.U64.to_be_bytes (toU64 w))
  rw [from_to_be_bytes, ofU64_toU64] at h
  have hv := congrArg UInt64.toNat h
  simpa [toNat_u64_from_be_bytes, wordBytes] using hv.symm

def wordsBytes (w : Vector UInt64 4) : List U8 :=
  wordBytes w[3] ++ wordBytes w[2] ++ wordBytes w[1] ++ wordBytes w[0]

@[simp] theorem wordsBytes_length (w : Vector UInt64 4) : (wordsBytes w).length = 32 := by
  simp [wordsBytes]

theorem wordsBytes_value (w : Vector UInt64 4) :
    bytesVal ((wordsBytes w).map ofU8) = valWords w := by
  simp only [wordsBytes, List.map_append, bytesVal_append, wordBytes_value,
    List.length_map, wordBytes_length]
  norm_num [valWords]
  ring

def writeBlocks (n width start : Nat) (chunks : Nat → List U8) (input : Slice U8) : Slice U8 :=
  (List.finRange n).foldl (fun out (j : Fin n) => out.setSlice! (start + width*j.val) (chunks j.val)) input

theorem writeBlocks_spec (n width start : Nat) (chunks : Nat → List U8) (input : Slice U8)
    (hlen : ∀ j < n, (chunks j).length = width) (hsize : start + width*n ≤ input.val.length) :
    let out := writeBlocks n width start chunks input
    out.val.length = input.val.length ∧
      (∀ j < n, ∀ b < width, out.val[start + width*j+b]! = (chunks j)[b]!) ∧
      (∀ i, i < start ∨ start + width*n ≤ i → out.val[i]? = input.val[i]?) := by
  let inv (k : Nat) (out : Slice U8) :=
    out.val.length = input.val.length ∧
      (∀ j < k, ∀ b < width, out.val[start + width*j+b]! = (chunks j)[b]!) ∧
      (∀ i, i < start ∨ start + width*k ≤ i → out.val[i]? = input.val[i]?)
  apply foldl_finRange_inv (inv := inv)
  · intro out k hk
    rcases hk with ⟨hs, hv, hf⟩
    refine ⟨by simpa using hs, ?_, ?_⟩
    · intro j hj b hb
      rw [Slice.setSlice!_val]
      by_cases hjk : j < k.val
      · have hmul := Nat.mul_le_mul_left width (Nat.succ_le_of_lt hjk)
        simp only [Nat.mul_succ] at hmul
        rw [List.getElem!_setSlice!_prefix _ _ _ _ (by omega)]
        exact hv j hjk b hb
      · have he : j = k.val := by omega
        subst j
        rw [List.getElem!_setSlice!_middle]
        · simp
        · rw [hlen _ k.isLt, hs]
          have hmul := Nat.mul_le_mul_left width (Nat.succ_le_of_lt k.isLt)
          simp only [Nat.mul_succ] at hmul
          omega
    · intro i hi
      simp only [Nat.mul_add, Nat.mul_one] at hi
      rw [Slice.setSlice!_val, List.setSlice!_getElem?_same]
      · apply hf i
        rcases hi with hi | hi
        · exact Or.inl hi
        · exact Or.inr (by omega)
      · rw [hlen _ k.isLt]
        omega
  · refine ⟨rfl, ?_, ?_⟩
    · intro j hj; omega
    · intro i hi; rfl

theorem slice_index_mut_ok (s : Slice U8) (a b : Usize) (hab : a.val ≤ b.val)
    (hb : b.val ≤ s.val.length) :
    core.slice.index.Slice.index_mut (core.slice.index.SliceIndexRangeUsizeSlice U8) s
      { start := a, «end» := b } =
      ok (⟨s.val.slice a.val b.val, le_trans (List.slice_length_le _ _ _) s.property⟩,
        fun t => s.setSlice! a.val t.val) := by
  simp only [core.slice.index.Slice.index_mut,
    core.slice.index.SliceIndexRangeUsizeSlice.index_mut, UScalar.le_equiv]
  rw [if_pos (by simp only [Slice.length]; exact ⟨hab, hb⟩)]
  rfl

theorem wordsBytes_get (w : Vector UInt64 4) (k b : Nat) (hk : k < 4) (hb : b < 8) :
    (wordsBytes w)[8*k+b]! = (wordBytes w[3-k]!)[b]! := by
  interval_cases k <;>
    simp (disch := (simp only [List.length_append, wordBytes_length]; omega)) only
      [wordsBytes, Nat.reduceMul, Nat.reduceSub, Nat.zero_add,
        getElem!_pos w 0 (by decide), getElem!_pos w 1 (by decide),
        getElem!_pos w 2 (by decide), getElem!_pos w 3 (by decide),
        List.getElem!_append_left, List.getElem!_append_right, List.length_append,
        wordBytes_length, Nat.reduceAdd] <;>
    congr 1 <;> omega


def blockBytes (block : M512) : List U8 :=
  wordBytes block[0] ++ wordBytes block[1] ++ wordBytes block[2] ++ wordBytes block[3] ++
  wordBytes block[4] ++ wordBytes block[5] ++ wordBytes block[6] ++ wordBytes block[7]

@[simp] theorem blockBytes_length (block : M512) : (blockBytes block).length = 64 := by
  simp [blockBytes]

theorem blockBytes_get (block : M512) (k b : Nat) (hk : k < 8) (hb : b < 8) :
    (blockBytes block)[8*k+b]! = (wordBytes block[k]!)[b]! := by
  interval_cases k <;>
    simp (disch := (simp only [List.length_append, wordBytes_length]; omega)) only
      [blockBytes, Nat.reduceMul, Nat.zero_add,
        getElem!_pos block 0 (by decide), getElem!_pos block 1 (by decide),
        getElem!_pos block 2 (by decide), getElem!_pos block 3 (by decide),
        getElem!_pos block 4 (by decide), getElem!_pos block 5 (by decide),
        getElem!_pos block 6 (by decide), getElem!_pos block 7 (by decide),
        List.getElem!_append_left, List.getElem!_append_right, List.length_append,
        wordBytes_length, Nat.reduceAdd] <;>
    congr 1 <;> omega

theorem writeBlocks_eq_setSlice (n width start : Nat) (chunks : Nat → List U8)
    (input : Slice U8) (xs : List U8)
    (hlen : ∀ j < n, (chunks j).length = width) (hsize : start + width*n ≤ input.val.length)
    (hxs : xs.length = width*n)
    (hget : ∀ k < n, ∀ b < width, xs[width*k+b]! = (chunks k)[b]!) :
    writeBlocks n width start chunks input = input.setSlice! start xs := by
  have h := writeBlocks_spec n width start chunks input hlen hsize
  apply Subtype.ext
  apply List.ext_getElem
  · simpa using h.1
  · intro i hi hi'
    rw [← getElem!_pos _ i hi, ← getElem!_pos _ i hi', Slice.setSlice!_val]
    by_cases hb : start ≤ i ∧ i < start+width*n
    · have hw : 0 < width := by
        by_contra hn
        have hw0 : width = 0 := by omega
        simp [hw0] at hb
        omega
      let k := (i-start)/width
      let b := (i-start)%width
      have hk : k < n := by dsimp [k]; exact (Nat.div_lt_iff_lt_mul hw).2 (by rw [Nat.mul_comm]; omega)
      have hb' : b < width := Nat.mod_lt _ hw
      have he : start + width*k+b = i := by dsimp [k,b]; have := Nat.mod_add_div (i-start) width; omega
      rw [← he, h.2.1 k hk b hb', List.getElem!_setSlice!_middle]
      · rw [show start + width*k+b-start = width*k+b by omega]
        exact (hget k hk b hb').symm
      · rw [hxs]; omega
    · have hv := congrArg (fun x : Option U8 => x.getD default) (h.2.2 i (by omega))
      have hv' : (writeBlocks n width start chunks input).val[i]! = input.val[i]! := by
        simpa using hv
      rw [hv', List.getElem!_setSlice!_same]
      rw [hxs]
      omega

theorem store_block_loop_refines (block : M512) (input : Slice U8) (offset : Usize)
    (hsize : offset.val + 64 ≤ input.val.length) :
    fr8.u256x8.store_block block input offset =
      ok (writeBlocks 8 8 offset.val
        (fun k => (core.num.U64.to_le_bytes (toU64 block[k]!)).val) input) := by
  unfold fr8.u256x8.store_block
  rw [Simd.lanes_refines]
  simp only [bind_tc_ok, Simd.lanes]
  unfold fr8.u256x8.store_block_loop writeBlocks
  rw [fr8.LANES]
  refine loop_range_inv (n := 8) _ 8#usize rfl id
    (fun out (k : Fin 8) => out.setSlice! (offset.val + 8*k.val)
      (core.num.U64.to_le_bytes (toU64 block[k.val]!)).val) id
    (fun _ out => out.val.length = input.val.length) ?_ ?_ ?_ 0#usize input (by simp) rfl
  · intro out k hk
    simpa using hk
  · intro r out he hs ho hn
    simp_body fr8.u256x8.store_block_loop.body hn
  · intro r r' out k he hs he' hs' ho hn
    have hk : r.start.val < 8 := by rw [hs]; exact k.isLt
    have hmax : input.val.length < 2^UScalarTy.Usize.numBits := by
      have hp := input.property
      simp only [Usize.max, Usize.numBits] at hp
      have := Nat.two_pow_pos UScalarTy.Usize.numBits
      omega
    have hplatform := two_pow_32_le_usize
    simp only [UScalarTy.Usize_numBits_eq] at hmax hplatform
    simp_body fr8.u256x8.store_block_loop.body hn
    simp (disch := (simp [List.slice_length, Array.to_slice]; omega)) only [usize_mul_ok, add_ok,
      bind_tc_ok, UScalar.ofNatCore_val_eq]
    rw [slice_index_mut_ok _ _ _ (by simp) (by simp; omega)]
    simp only [bind_tc_ok, Function.uncurry_apply_pair]
    rw [index_usize_toArray toU64 block rfl _ hk]
    simp only [bind_tc_ok, lift]
    rw [copy_from_slice_ok]
    · simp only [bind_tc_ok]
      simp [hs]
    · change (out.val.slice (offset.val + 8*r.start.val)
        (offset.val + 8*r.start.val + 8)).length =
          (core.num.U64.to_le_bytes (toU64 block[r.start.val])).val.length
      rw [(core.num.U64.to_le_bytes (toU64 block[r.start.val])).property]
      change _ = 8
      rw [List.slice_length]
      omega

theorem store_block_refines (block swapped : M512) (input : Slice U8) (offset : Usize)
    (hswap : ∀ k : Fin 8, (core.num.U64.to_le_bytes (toU64 swapped[k])).val = wordBytes block[k])
    (hsize : offset.val + 64 ≤ input.val.length) :
    fr8.u256x8.store_block swapped input offset = ok (input.setSlice! offset.val (blockBytes block)) := by
  rw [store_block_loop_refines swapped input offset hsize]
  apply congrArg ok
  apply writeBlocks_eq_setSlice
  · intro j hj
    exact (core.num.U64.to_le_bytes (toU64 swapped[j]!)).property
  · exact hsize
  · exact blockBytes_length block
  · intro k hk b hb
    rw [blockBytes_get block k b hk hb]
    simpa [getElem!_pos block k hk, getElem!_pos swapped k hk] using
      congrArg (fun xs : List U8 => xs[b]!) (hswap ⟨k,hk⟩).symm

end LeanBlsSimd.Kzg.Extender.Kernel.BytePacking
