import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Bytes
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8BytesSerialize
import LeanBlsSimd.Refines.DecompressG2
import LeanBlsSimd.Kzg.ByteSerialization

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel.BytePacking

set_option exponentiation.threshold 1000
set_option maxRecDepth 4000
set_option maxHeartbeats 2000000

private theorem packed_word (a b : UInt64) (r l : Nat) (hr : r < 64) (hl : l < 64)
    (ha : a.toNat / 2 ^ r < 2 ^ l) :
    ((a >>> r.toUInt64) ||| (b <<< l.toUInt64)).toNat =
      a.toNat / 2 ^ r + b.toNat % 2 ^ (64-l) * 2 ^ l := by
  have hr64 : r.toUInt64.toNat % 64 = r := by
    rw [Nat.toUInt64_eq, UInt64.toNat_ofNat']; omega
  have hl64 : l.toUInt64.toNat % 64 = l := by
    rw [Nat.toUInt64_eq, UInt64.toNat_ofNat']; omega
  rw [UInt64.toNat_or, UInt64.toNat_shiftRight, UInt64.toNat_shiftLeft, hr64, hl64,
    Nat.shiftRight_eq_div_pow, Nat.shiftLeft_eq,
    show (2 : Nat)^64 = 2^(64-l) * 2^l by rw [← pow_add]; congr 1; omega,
    Nat.mul_mod_mul_right, or_mul_two_pow ha]

theorem pack_value (x : Vector UInt64 5) (hn : ∀ j : Fin 5, x[j].toNat < 2^52)
    (hb : val52 x < 2^256) : valWords (pack x) = val52 x := by
  have h0 : x[0].toNat < 2^52 := hn 0
  have h1 : x[1].toNat < 2^52 := hn 1
  have h2 : x[2].toNat < 2^52 := hn 2
  have h3 : x[3].toNat < 2^52 := hn 3
  have h4 : x[4].toNat < 2^52 := hn 4
  have ht : x[4].toNat < 2^48 := by unfold val52 at hb; omega
  have w0 : (pack x)[0].toNat = x[0].toNat + x[1].toNat % 2^12 * 2^52 := by
    simpa [pack] using packed_word x[0] x[1] 0 52 (by decide) (by decide) (by simpa using h0)
  have w1 : (pack x)[1].toNat = x[1].toNat / 2^12 + x[2].toNat % 2^24 * 2^40 := by
    simpa [pack] using packed_word x[1] x[2] 12 40 (by decide) (by decide) (by omega)
  have w2 : (pack x)[2].toNat = x[2].toNat / 2^24 + x[3].toNat % 2^36 * 2^28 := by
    simpa [pack] using packed_word x[2] x[3] 24 28 (by decide) (by decide) (by omega)
  have w3 : (pack x)[3].toNat = x[3].toNat / 2^36 + x[4].toNat * 2^16 := by
    change ((x[3] >>> (36 : UInt64)) ||| (x[4] <<< (16 : UInt64))).toNat = _
    have h := packed_word x[3] x[4] 36 16 (by decide) (by decide) (by omega)
    change ((x[3] >>> (36 : UInt64)) ||| (x[4] <<< (16 : UInt64))).toNat =
      x[3].toNat / 2^36 + x[4].toNat % 2^48 * 2^16 at h
    rw [Nat.mod_eq_of_lt ht] at h
    exact h
  rw [valWords, w0, w1, w2, w3, val52]
  omega

theorem pack_refines (x : Array U64 5#usize) :
    fr8.pack64 x = ok (toArray toU64 (pack (ofArray ofU64 x))) := by
  unfold fr8.pack64
  simp only [index_usize_eq x 0#usize (by decide), index_usize_eq x 1#usize (by decide),
    index_usize_eq x 2#usize (by decide), index_usize_eq x 3#usize (by decide),
    index_usize_eq x 4#usize (by decide), bind_tc_ok, lift]
  simp only [HShiftRight.hShiftRight, HShiftLeft.hShiftLeft, UScalar.shiftRight_IScalar,
    UScalar.shiftLeft_IScalar, UScalar.shiftRight, UScalar.shiftLeft, IScalar.toNat]
  simp only [show (52#i32).val = 52 by rfl, show (12#i32).val = 12 by rfl,
    show (40#i32).val = 40 by rfl, show (24#i32).val = 24 by rfl,
    show (28#i32).val = 28 by rfl, show (36#i32).val = 36 by rfl,
    show (16#i32).val = 16 by rfl]
  norm_num only [UScalarTy.U64_numBits_eq, Int.reduceLT, Nat.reduceLT, ↓reduceIte, bind_tc_ok]
  simp only [show Int.toNat (52:Int) = 52 from rfl, show Int.toNat (12:Int) = 12 from rfl,
    show Int.toNat (40:Int) = 40 from rfl, show Int.toNat (24:Int) = 24 from rfl,
    show Int.toNat (28:Int) = 28 from rfl, show Int.toNat (36:Int) = 36 from rfl,
    show Int.toNat (16:Int) = 16 from rfl, Nat.reduceLT, if_true, bind_tc_ok]
  apply congrArg ok
  apply Subtype.ext
  have hinj : Function.Injective (List.map ofU64) := by
    intro a b h
    have hh := congrArg (List.map toU64) h
    simpa [List.map_map, Function.comp_def] using hh
  apply hinj
  simp [Array.make, toArray, pack]

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

def store (self : Vector M512 5) : Vector (Vector UInt64 5) 8 :=
  (List.finRange 5).foldl (init := .replicate 8 (.replicate 5 0)) fun out (j : Fin 5) =>
    (List.finRange 8).foldl (init := out) fun out (lane : Fin 8) =>
      out.set lane (out[lane].set j self[j][lane])

theorem getElem_store_foldl_inner (v : Vector UInt64 8) (j : ℕ) (hj : j < 5) (l : Fin 8) :
    ∀ (ls : List (Fin 8)) (out : Vector (Vector UInt64 5) 8), ls.Nodup →
      (ls.foldl (fun out (lane : Fin 8) => out.set lane (out[lane].set j v[lane])) out)[l] =
        if l ∈ ls then out[l].set j v[l] else out[l]
  | [], out, _ => by simp
  | i :: ls, out, hnd => by
    rw [List.foldl_cons, getElem_store_foldl_inner v j hj l ls _ (List.nodup_cons.mp hnd).2]
    have hi := (List.nodup_cons.mp hnd).1
    by_cases hl : l ∈ ls
    · have : i ≠ l := fun h => hi (h ▸ hl)
      simp [hl, Fin.val_ne_of_ne this]
    · by_cases hil : i = l
      · subst hil; simp [hl]
      · simp [hl, Fin.val_ne_of_ne hil, Ne.symm hil]

theorem getElem_store (x : Vector M512 5) (l : Fin 8) : (store x)[l] = laneOf x l := by
  have outer : ∀ (js : List (Fin 5)) (out : Vector (Vector UInt64 5) 8) (j' : ℕ) (hj' : j' < 5),
      (js.foldl (fun out (j : Fin 5) =>
        (List.finRange 8).foldl (fun out (lane : Fin 8) =>
          out.set lane (out[lane].set j x[j][lane])) out) out)[l][j'] =
        if j' ∈ js.map (·.val) then x[j'][l] else out[l][j'] := by
    intro js
    induction js with
    | nil => simp
    | cons j js ih =>
      intro out j' hj'
      rw [List.foldl_cons, ih]
      rw [getElem_store_foldl_inner _ _ j.isLt l _ _ (List.nodup_finRange 8)]
      by_cases h : j' ∈ js.map (·.val)
      · simp [h]
      · by_cases hjj : j.val = j'
        · subst hjj; simp
        · simp [h, hjj, Ne.symm hjj]
  ext j' hj'
  rw [store, outer]
  simp [laneOf, hj']

theorem store_inner_refines (out : Vector (Vector UInt64 5) 8) (j : Usize) (hj : j.val < 5)
    (l : Vector UInt64 8) :
    fr8.Fr8.to_bytes_loop0_loop0 { start := 0#usize, «end» := fr8.LANES } (toArray (toArray toU64) out) j
        (toArray toU64 l) =
      ok (toArray (toArray toU64) ((List.finRange 8).foldl
        (fun out (lane : Fin 8) => out.set lane (out[lane].set j.val l[lane])) out)) := by
  unfold fr8.Fr8.to_bytes_loop0_loop0
  rw [fr8.LANES]
  refine loop_range (n := 8) _ 8#usize rfl (toArray (toArray toU64))
    (fun out (lane : Fin 8) => out.set lane (out[lane].set j.val l[lane])) (toArray (toArray toU64))
    out _ ?_ ?_ rfl
  · intro r m he hs hn
    simp_body fr8.Fr8.to_bytes_loop0_loop0.body hn
  · intro r r' m lane he hs he' hs' hn
    have hl : r.start.val < (8#usize).val := by rw [hs]; exact lane.isLt
    have hj' : j.val < (5#usize).val := hj
    simp_body fr8.Fr8.to_bytes_loop0_loop0.body hn
    simp only [index_usize_eq _ _ hl, bind_tc_ok, Array.index_mut_usize, update_eq _ _ _ hj']
    refine congrArg (fun s => ok (cont (r', s))) ?_
    apply Subtype.ext
    simp [hs, hj, List.map_set, Vector.toList_set]

theorem store_refines (self : fr8.Fr8) :
    fr8.Fr8.to_bytes_loop0 { start := 0#usize, «end» := fr8.LIMBS } self
      (Array.repeat 8#usize (Array.repeat 5#usize 0#u64)) = ok (toArray (toArray toU64) (store (ofArray id self))) := by
  unfold fr8.Fr8.to_bytes_loop0
  simp only [fr8.LIMBS]
  rw [show Array.repeat 8#usize (Array.repeat 5#usize 0#u64) =
    toArray (toArray toU64) (Vector.replicate 8 (Vector.replicate 5 0)) from
    by simp [toArray_replicate]; rfl]
  refine loop_range (n := 5) _ 5#usize rfl (fun out => (self, toArray (toArray toU64) out))
    (fun out (j : Fin 5) =>
      (List.finRange 8).foldl (fun out (lane : Fin 8) =>
        out.set lane (out[lane].set j (Simd.lanes (ofArray id self)[j])[lane])) out)
    (toArray (toArray toU64)) (Vector.replicate 8 (Vector.replicate 5 0)) _ ?_ ?_ rfl
  · intro r m he hs hn
    simp_body fr8.Fr8.to_bytes_loop0.body hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (5#usize).val := by rw [hs]; exact j.isLt
    simp_body fr8.Fr8.to_bytes_loop0.body hn
    simp only [index_usize_eq _ _ hj, bind_tc_ok, Simd.lanes_refines]
    rw [store_inner_refines _ _ (by rw [hs]; exact j.isLt)]
    simp [hs]


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

theorem words_to_bytes_loop_refines (w : Vector UInt64 4) (input : Slice U8) (offset : Usize)
    (hsize : offset.val + 32 ≤ input.val.length) :
    fr8.words_to_bytes (toArray toU64 w) input offset =
      ok (writeBlocks 4 8 offset.val (fun k => wordBytes w[3-k]!) input) := by
  unfold fr8.words_to_bytes fr8.words_to_bytes_loop writeBlocks
  refine loop_range_inv (n := 4) _ 4#usize rfl id
    (fun out (k : Fin 4) => out.setSlice! (offset.val + 8*k.val) (wordBytes w[3-k.val]!)) id
    (fun _ out => out.val.length = input.val.length) ?_ ?_ ?_ 0#usize input (by simp) rfl
  · intro out k hk
    simpa using hk
  · intro r out he hs ho hn
    simp_body fr8.words_to_bytes_loop.body hn
  · intro r r' out k he hs he' hs' ho hn
    have hk : r.start.val < 4 := by rw [hs]; exact k.isLt
    have hmax : input.val.length < 2^UScalarTy.Usize.numBits := by
      have hp := input.property
      simp only [Usize.max, Usize.numBits] at hp
      have := Nat.two_pow_pos UScalarTy.Usize.numBits
      omega
    have hplatform := two_pow_32_le_usize
    simp only [UScalarTy.Usize_numBits_eq] at hmax hplatform
    simp_body fr8.words_to_bytes_loop.body hn
    simp (disch := (simp [List.slice_length, Array.to_slice]; omega)) only [usize_mul_ok, add_ok,
      sub_ok, bind_tc_ok, UScalar.ofNatCore_val_eq]
    rw [slice_index_mut_ok _ _ _ (by simp) (by simp; omega)]
    simp only [bind_tc_ok, Function.uncurry_apply_pair]
    rw [index_usize_toArray toU64 w rfl _ (by simp; omega)]
    simp only [bind_tc_ok, lift]
    rw [copy_from_slice_ok]
    · simp only [bind_tc_ok]
      simp [wordBytes, hs, getElem!_pos w (3-k.val) (by omega)]
    · change (out.val.slice (offset.val + 8*r.start.val)
        (offset.val + 8*r.start.val + 8)).length = (wordBytes w[3-r.start.val]).length
      rw [wordBytes_length, List.slice_length]
      omega

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

theorem words_to_bytes_refines (w : Vector UInt64 4) (input : Slice U8) (offset : Usize)
    (hsize : offset.val + 32 ≤ input.val.length) :
    fr8.words_to_bytes (toArray toU64 w) input offset = ok (input.setSlice! offset.val (wordsBytes w)) := by
  rw [words_to_bytes_loop_refines w input offset hsize]
  apply congrArg ok
  have h := writeBlocks_spec 4 8 offset.val (fun k => wordBytes w[3-k]!) input
    (by simp) hsize
  apply Subtype.ext
  apply List.ext_getElem
  · simpa using h.1
  · intro i hi hi'
    rw [← getElem!_pos _ i hi, ← getElem!_pos _ i hi', Slice.setSlice!_val]
    by_cases hb : offset.val ≤ i ∧ i < offset.val+32
    · let k := (i-offset.val)/8
      let b := (i-offset.val)%8
      have hk : k < 4 := by dsimp [k]; omega
      have hb' : b < 8 := by dsimp [b]; omega
      have he : offset.val + 8*k+b = i := by dsimp [k,b]; omega
      rw [← he, h.2.1 k hk b hb', List.getElem!_setSlice!_middle]
      · rw [show offset.val + 8*k+b-offset.val = 8*k+b by omega]
        exact (wordsBytes_get w k b hk hb').symm
      · rw [wordsBytes_length]
        omega
    · have hv := congrArg (fun x : Option U8 => x.getD default) (h.2.2 i (by omega))
      have hv' : (writeBlocks 4 8 offset.val (fun k => wordBytes w[3-k]!) input).val[i]! = input.val[i]! := by
        simpa using hv
      rw [hv', List.getElem!_setSlice!_same]
      rw [wordsBytes_length]
      omega

theorem to_bytes_loop1_refines (lanes : Vector (Vector UInt64 5) 8)
    (input : Slice U8) (offset : Usize) (hsize : offset.val+256 ≤ input.val.length) :
    fr8.Fr8.to_bytes_loop1 { start := 0#usize, «end» := fr8.LANES } input offset
      (toArray (toArray toU64) lanes) =
      ok (writeBlocks 8 32 offset.val (fun k => wordsBytes (pack lanes[k]!)) input) := by
  unfold fr8.Fr8.to_bytes_loop1 writeBlocks
  rw [fr8.LANES]
  refine loop_range_inv (n := 8) _ 8#usize rfl id
    (fun out (k : Fin 8) => out.setSlice! (offset.val + 32*k.val) (wordsBytes (pack lanes[k.val]!))) id
    (fun _ out => out.val.length = input.val.length) ?_ ?_ ?_ 0#usize input (by simp) rfl
  · intro out k hk
    simpa using hk
  · intro r out he hs ho hn
    simp_body fr8.Fr8.to_bytes_loop1.body hn
  · intro r r' out k he hs he' hs' ho hn
    have hk : r.start.val < 8 := by rw [hs]; exact k.isLt
    have hmax : input.val.length < 2^UScalarTy.Usize.numBits := by
      have hp := input.property
      simp only [Usize.max, Usize.numBits] at hp
      have := Nat.two_pow_pos UScalarTy.Usize.numBits
      omega
    have hplatform := two_pow_32_le_usize
    simp only [UScalarTy.Usize_numBits_eq] at hmax hplatform
    simp_body fr8.Fr8.to_bytes_loop1.body hn
    rw [index_usize_toArray (toArray toU64) lanes rfl _ hk]
    simp only [bind_tc_ok]
    rw [pack_refines]
    simp only [ofArray_toArray_ofU64, bind_tc_ok]
    simp (disch := (simp; omega)) only [usize_mul_ok, add_ok, bind_tc_ok, UScalar.ofNatCore_val_eq]
    rw [words_to_bytes_refines _ _ _ (by simp; omega)]
    simp [hs]

theorem val52_eq_model (x : Vector UInt64 5) : val52 x = FrModel.val x := by
  unfold FrModel.val
  rw [FrModel.sum_fin_limbs]
  simp only [Fin.getElem_fin, FrModel.val_fin_LIMBS, FrModel.LIMB_BITS, Nat.reduceMul,
    pow_zero, mul_one]
  rfl

theorem laneOf_eq_model (a : fr8.Fr8) (lane : Fin 8) :
    laneOf (ofArray id a) lane = (FrModel.ofFr8 a).lane lane := rfl

theorem val52_store (a : fr8.Fr8) (lane : Fin 8) :
    val52 (store (ofArray id a))[lane] = laneNat a lane := by
  rw [getElem_store]
  change val52 ((FrModel.ofFr8 a).lane lane) = laneNat a lane
  rw [val52_eq_model, laneNat_eq_val]

theorem normal_store (a : fr8.Fr8) (hn : Normalized a) (lane : Fin 8) :
    ∀ j : Fin 5, ((store (ofArray id a))[lane])[j].toNat < 2^52 := by
  rw [getElem_store]
  change ∀ j : Fin 5, ((FrModel.ofFr8 a).lane lane)[j].toNat < 2^52
  exact (normalized_iff_model a).mp hn lane

theorem packed_store_value (a : fr8.Fr8) (hn : Normalized a) (lane : Fin 8)
    (hb : laneNat a lane < 2^256) :
    valWords (pack (store (ofArray id a))[lane]) = laneNat a lane := by
  calc
    _ = val52 (store (ofArray id a))[lane] :=
      pack_value _ (normal_store a hn lane) (by rwa [val52_store])
    _ = laneNat a lane := val52_store a lane

theorem encoded_bytes_refinement (a : fr8.Fr8) (ha : Bounded a) (input : Slice U8) (offset : Usize)
    (hsize : offset.val + 256 ≤ input.val.length) :
    ∃ out, fr8.Fr8.to_bytes a input offset = ok out ∧ out.val.length = input.val.length ∧
      (∀ lane : Fin 8,
        (bytes out.val).extract (offset.val + 32 * lane.val) (offset.val + 32 * (lane.val + 1)) =
          blsFieldToBytes (laneValue a lane)) ∧
      (∀ i : Fin input.val.length, i.val < offset.val ∨ offset.val + 256 ≤ i.val →
        out.val[i.val]? = input.val[i.val]?) := by
  obtain ⟨canonical, hc, hn, hv⟩ := canonical_refinement a ha
  let lanes := store (ofArray id canonical)
  let chunks (k : Nat) := wordsBytes (pack lanes[k]!)
  let out := writeBlocks 8 32 offset.val chunks input
  have hs := writeBlocks_spec 8 32 offset.val chunks input (by intros; simp [chunks]) hsize
  refine ⟨out, ?_, hs.1, ?_, fun i hi => hs.2.2 i.val hi⟩
  · unfold fr8.Fr8.to_bytes
    rw [hc]
    simp only [bind_tc_ok]
    rw [store_refines]
    simp only [bind_tc_ok]
    exact to_bytes_loop1_refines lanes input offset hsize
  · intro lane
    have hbound : offset.val + 32*lane.val+32 ≤ out.val.length := by
      change _ ≤ (writeBlocks 8 32 offset.val chunks input).val.length
      rw [hs.1]
      have := lane.isLt
      omega
    rw [show offset.val + 32*(lane.val+1) = offset.val+32*lane.val+32 by omega]
    rw [extract_eq_bytes out (chunks lane.val) (offset.val+32*lane.val) 32
      (by simp [chunks]) hbound (fun i hi => hs.2.1 lane.val lane.isLt i hi)]
    apply bytes_eq_lane _ a lane (by simp [chunks])
    dsimp only [chunks]
    rw [getElem!_pos lanes lane.val lane.isLt, wordsBytes_value]
    have hb : laneNat canonical lane < 2^256 := by
      rw [hv]
      have hm := Nat.mod_lt (laneNat a lane) (show 0 < Fr.modulus by decide)
      have hp : Fr.modulus < 2^256 := by decide
      omega
    simpa only [lanes, Fin.getElem_fin] using
      (packed_store_value canonical hn lane hb).trans (hv lane)

end LeanBlsSimd.Kzg.Extender.Kernel.BytePacking
