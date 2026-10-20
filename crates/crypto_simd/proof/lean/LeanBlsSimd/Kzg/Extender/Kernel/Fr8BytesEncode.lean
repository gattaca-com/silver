import LeanBlsSimd.Kzg.Extender.Kernel.Fr8WordStore
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Words
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Endian
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

theorem vector_to_bytes_loop_refines (blocks : Vector M512 4) (input : Slice U8)
    (hsize : 256 ≤ input.val.length) :
    fr8.u256x8.U256x8.to_bytes_loop { start := 0#usize, «end» := fr8.u256x8.WORDS }
      (toArray id blocks) input =
      ok (writeBlocks 4 64 0 (fun k => blockBytes blocks[k]!) input) := by
  unfold fr8.u256x8.U256x8.to_bytes_loop writeBlocks
  rw [fr8.u256x8.WORDS]
  refine loop_range_inv (n := 4) _ 4#usize rfl id
    (fun out (k : Fin 4) => out.setSlice! (64*k.val) (blockBytes blocks[k.val]!)) id
    (fun _ out => out.val.length = input.val.length) ?_ ?_ ?_ 0#usize input (by simp) rfl
  · intro out k hk
    simpa using hk
  · intro r out he hs ho hn
    simp_body fr8.u256x8.U256x8.to_bytes_loop.body hn
  · intro r r' out k he hs he' hs' ho hn
    have hk : r.start.val < 4 := by rw [hs]; exact k.isLt
    have hplatform := two_pow_32_le_usize
    simp only [UScalarTy.Usize_numBits_eq] at hplatform
    simp_body fr8.u256x8.U256x8.to_bytes_loop.body hn
    rw [index_usize_toArray id blocks rfl _ hk]
    simp only [bind_tc_ok]
    rw [swap_bytes_refines]
    simp only [bind_tc_ok]
    simp (disch := (simp <;> omega)) only [usize_mul_ok, bind_tc_ok, UScalar.ofNatCore_val_eq]
    rw [store_block_refines (blocks[r.start.val]) _ _ _ ?_ (by simp; omega)]
    · simp [hs]
    · intro lane
      simpa [wordBytes] using congrArg Subtype.val (to_le_bytes_swapWord (blocks[r.start.val][lane]))

theorem blockBytes_wordBlocks_get (w : Vector M512 4) (lane : Fin 8) (b : Nat) (hb : b < 32) :
    (blockBytes (wordBlocks w)[lane.val/2]!)[32*(lane.val%2)+b]! =
      (wordsBytes (wordLane w lane))[b]! := by
  have hhalf : lane.val / 2 < 4 := by omega
  have hk : 4*(lane.val%2)+b/8 < 8 := by omega
  have hbyte : b % 8 < 8 := Nat.mod_lt _ (by decide)
  have hindex : 32*(lane.val%2)+b = 8*(4*(lane.val%2)+b/8)+b%8 := by omega
  rw [hindex, blockBytes_get _ _ _ hk hbyte]
  conv_rhs => rw [show b = 8*(b/8)+b%8 by omega]
  rw [wordsBytes_get _ _ _ (by omega) hbyte]
  have hword : (4*(lane.val%2)+b/8)%4 = b/8 := by omega
  have hlane : 2*(lane.val/2)+(4*(lane.val%2)+b/8)/4 = lane.val := by omega
  rw [getElem!_pos (wordBlocks w) (lane.val/2) hhalf,
    getElem!_pos ((wordBlocks w)[lane.val/2]) (4*(lane.val%2)+b/8) hk,
    getElem!_pos (wordLane w lane) (3-b/8) (by omega)]
  simp only [wordBlocks, Vector.getElem_ofFn, wordLane, laneOf,
    Vector.getElem_map, Fin.getElem_fin, hword, hlane]

theorem vector_to_bytes_refines (w : Vector M512 4) (input : Slice U8) (offset : Usize)
    (hsize : offset.val + 256 ≤ input.val.length) :
    fr8.u256x8.U256x8.to_bytes (toArray id w) input offset =
      ok (writeBlocks 8 32 offset.val (fun k => wordsBytes (wordLane w ⟨k%8, Nat.mod_lt _ (by decide)⟩)) input) := by
  let chunks (k : Nat) := wordsBytes (wordLane w ⟨k%8, Nat.mod_lt _ (by decide)⟩)
  let sub : Slice U8 := ⟨input.val.slice offset.val (offset.val+256),
    le_trans (List.slice_length_le _ _ _) input.property⟩
  have hsub : sub.val.length = 256 := by simp [sub, List.slice_length]; omega
  let stored := writeBlocks 4 64 0 (fun k => blockBytes (wordBlocks w)[k]!) sub
  have hs := writeBlocks_spec 4 64 0 (fun k => blockBytes (wordBlocks w)[k]!) sub
    (by intros; simp) (by omega)
  have ht := writeBlocks_spec 8 32 offset.val chunks input (by intros; simp [chunks]) hsize
  have hmax : input.val.length < 2^UScalarTy.Usize.numBits := by
    have hp := input.property
    simp only [Usize.max, Usize.numBits] at hp
    have := Nat.two_pow_pos UScalarTy.Usize.numBits
    omega
  have hplatform := two_pow_32_le_usize
  simp only [UScalarTy.Usize_numBits_eq] at hmax hplatform
  unfold fr8.u256x8.U256x8.to_bytes
  rw [blocks_refines]
  simp only [fr8.LANES, bind_tc_ok]
  rw [usize_mul_ok 32#usize 8#usize (by decide)]
  simp only [bind_tc_ok]
  rw [add_ok _ _ (by change offset.val + 256 < 2^UScalarTy.Usize.numBits; simp only [UScalarTy.Usize_numBits_eq]; omega)]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  rw [slice_index_mut_ok _ _ _ (by simp) (by simp; omega)]
  simp only [bind_tc_ok, Function.uncurry_apply_pair]
  rw [vector_to_bytes_loop_refines _ _ (by change 256 ≤ sub.val.length; omega)]
  simp only [bind_tc_ok]
  change ok (input.setSlice! offset.val stored.val) = ok (writeBlocks 8 32 offset.val chunks input)
  apply congrArg ok
  generalize hstored : stored = storedOut at ⊢
  dsimp only [stored] at hstored
  rw [hstored] at hs
  generalize houtput : writeBlocks 8 32 offset.val chunks input = output at ht ⊢
  apply Subtype.ext
  apply List.ext_getElem
  · simpa using ht.1.symm
  · intro i hi hi'
    rw [← getElem!_pos _ i hi, ← getElem!_pos _ i hi', Slice.setSlice!_val]
    by_cases hb : offset.val ≤ i ∧ i < offset.val+256
    · let lane : Fin 8 := ⟨(i-offset.val)/32, by omega⟩
      let b := (i-offset.val)%32
      have hb32 : b < 32 := Nat.mod_lt _ (by decide)
      have hi32 : offset.val+32*lane.val+b = i := by dsimp [lane,b]; omega
      have hi64 : 64*(lane.val/2)+(32*(lane.val%2)+b) = i-offset.val := by
        dsimp [lane,b]; omega
      have hb64 : 32*(lane.val%2)+b < 64 := by omega
      rw [List.getElem!_setSlice!_middle input.val storedOut.val offset.val i (by rw [hs.1,hsub]; omega)]
      rw [← hi64]
      have hget := hs.2.1 (lane.val/2) (by have := lane.isLt; omega)
        (32*(lane.val%2)+b) hb64
      simp only [Nat.zero_add] at hget
      rw [hget, blockBytes_wordBlocks_get w lane b hb32, ← hi32, ht.2.1 lane.val lane.isLt b hb32]
      simp [chunks, Nat.mod_eq_of_lt lane.isLt]
    · rw [List.getElem!_setSlice!_same]
      · have hget := congrArg (fun x : Option U8 => x.getD default) (ht.2.2 i (by omega))
        simpa using hget.symm
      · change i < offset.val ∨ offset.val + storedOut.val.length ≤ i
        rw [hs.1,hsub]
        omega

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
    have hnormal : ∀ j : Fin 5, ∀ lane : Fin 8, (ofArray id canonical)[j][lane].toNat < 2^52 := by
      intro j lane
      have h := (normalized_iff_model canonical).mp hn lane j
      change ((ofArray id canonical).map (fun x => x[lane]))[j.val].toNat < 2^52 at h
      rw [Vector.getElem_map] at h
      exact h
    have hpack := vectorPack_refines (ofArray id canonical) hnormal
    rw [toArray_ofArray (f := id) (g := id) (m := 5) (fun _ => rfl) canonical rfl rfl] at hpack
    rw [hpack]
    simp only [bind_tc_ok]
    rw [vector_to_bytes_refines _ _ _ hsize]
    apply congrArg ok
    unfold writeBlocks
    apply congrArg (fun f => (List.finRange 8).foldl f input)
    funext state k
    apply congrArg (fun xs => state.setSlice! (offset.val + 32*k.val) xs)
    dsimp only [chunks]
    rw [getElem!_pos lanes k.val k.isLt]
    change wordsBytes (wordLane (vectorPack (ofArray id canonical)) ⟨k.val%8, _⟩) =
      wordsBytes (pack (store (ofArray id canonical))[k])
    rw [getElem_store]
    apply congrArg wordsBytes
    ext j hj
    simp [wordLane, vectorPack, laneOf, Nat.mod_eq_of_lt k.isLt]
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
