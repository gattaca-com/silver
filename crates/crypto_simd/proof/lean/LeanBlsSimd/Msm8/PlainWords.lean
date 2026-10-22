import LeanBlsSimd.Kzg.Extender.Kernel.Fr8
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Mul
import LeanBlsSimd.Refines.Fp8

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

open EthCryptographySpecs Bls Kzg
open silver_crypto_simd.kzg
open LeanBlsSimd
namespace LeanBlsSimd.PlainWords

abbrev Word := Aeneas.Std.Array U64 4#usize

def rawWord (w : Array (Aeneas.Std.Array U64 8#usize) 4#usize) (lane : ℕ) : Aeneas.Std.Array U64 4#usize :=
  Array.make 4#usize [w.val[0]!.val[lane]!, w.val[1]!.val[lane]!,
    w.val[2]!.val[lane]!, w.val[3]!.val[lane]!] (by rfl)

theorem push_loop_refines (w : Array (Aeneas.Std.Array U64 8#usize) 4#usize)
    (words : alloc.vec.Vec Word) (count lane : Usize)
    (hc : count.val ≤ 8) (hl : lane.val ≤ count.val)
    (hroom : words.val.length + (count.val - lane.val) ≤ Usize.max) :
    ∃ out, fr8.u256x8.U256x8.push_words_loop words count w lane = ok out ∧
      out.val = words.val ++ (List.range' lane.val (count.val - lane.val)).map (rawWord w) := by
  induction hn : count.val - lane.val generalizing words lane with
  | zero =>
    refine ⟨words, ?_, by simp⟩
    unfold fr8.u256x8.U256x8.push_words_loop
    rw [loop.eq_1]
    have h : ¬lane.val < count.val := by omega
    simp only [fr8.u256x8.U256x8.push_words_loop.body, UScalar.lt_equiv, h, if_false]
  | succ n ih =>
    have hlt : lane.val < count.val := by omega
    have h8 : lane.val < 8 := by omega
    have hpush : words.val.length < Usize.max := by omega
    obtain ⟨nextWords, hpush, hw⟩ := WP.spec_imp_exists (alloc.vec.Vec.push_spec words (rawWord w lane.val) hpush)
    have hadd : lane.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
      have := two_pow_32_le_usize
      omega
    let next : Usize := UScalar.ofNatCore (lane.val + 1) hadd
    have hv : next.val = lane.val + 1 := rfl
    have hbody : fr8.u256x8.U256x8.push_words_loop.body count w words lane =
        ok (cont (nextWords,next)) := by
      simp only [fr8.u256x8.U256x8.push_words_loop.body, UScalar.lt_equiv, hlt, if_true]
      simp only [index_usize_eq w 0#usize (by decide), index_usize_eq w 1#usize (by decide),
        index_usize_eq w 2#usize (by decide), index_usize_eq w 3#usize (by decide), bind_tc_ok]
      have hix (r : Aeneas.Std.Array U64 8#usize) :
          Array.index_usize r lane = ok r.val[lane.val]! := by
        rw [index_usize_eq r lane h8]
        rw [getElem!_pos r.val lane.val (by rw [r.property]; exact h8)]
      simp only [hix, bind_tc_ok, UScalar.ofNatCore_val_eq]
      have he : (Array.make 4#usize [w.val[0].val[lane.val]!, w.val[1].val[lane.val]!,
          w.val[2].val[lane.val]!, w.val[3].val[lane.val]!] (by rfl)) = rawWord w lane.val := by
        simp [rawWord, getElem!_pos, w.property]
      rw [he, hpush]
      simp only [bind_tc_ok]
      rw [add_ok _ _ hadd]
      rfl
    obtain ⟨out, hout, hval⟩ := ih nextWords next (by omega)
      (by rw [hw, List.length_append, List.length_singleton]; omega) (by omega)
    refine ⟨out, ?_, ?_⟩
    · unfold fr8.u256x8.U256x8.push_words_loop
      change loop (fun p => fr8.u256x8.U256x8.push_words_loop.body count w p.1 p.2) (words,lane) = _
      rw [loop.eq_1, hbody]
      exact hout
    · rw [hval, hw, List.range'_succ, List.map_cons]
      simp only [hv, List.append_assoc, List.singleton_append]

def wordsMatrix (v : fr8.u256x8.U256x8) : Array (Aeneas.Std.Array U64 8#usize) 4#usize :=
  toArray (toArray toU64) (ofArray id v)

theorem push_words_refines (v : fr8.u256x8.U256x8)
    (words : alloc.vec.Vec Word) (count : Usize)
    (hc : count.val ≤ 8) (hroom : words.val.length + count.val ≤ Usize.max) :
    ∃ out, fr8.u256x8.U256x8.push_words v words count = ok out ∧
      out.val = words.val ++ (List.range count.val).map (rawWord (wordsMatrix v)) := by
  obtain ⟨out, hout, hval⟩ := push_loop_refines (wordsMatrix v) words count 0#usize hc (by simp) (by simpa using hroom)
  refine ⟨out, ?_, by simpa [List.range_eq_range'] using hval⟩
  simp only [fr8.u256x8.U256x8.push_words,
    index_usize_eq v 0#usize (by decide), index_usize_eq v 1#usize (by decide),
    index_usize_eq v 2#usize (by decide), index_usize_eq v 3#usize (by decide),
    Simd.lanes_refines, bind_tc_ok]
  convert hout using 1
  congr 1
  apply Subtype.ext
  simp only [wordsMatrix, toArray, ofArray, Vector.toList, List.map_map, Simd.lanes]
  have h : v.val.length = 4 := v.property
  exact (List.ext_getElem (by simp [h]) (by
    intro i hi hi'
    have hi4 : i < 4 := by simpa using hi
    interval_cases i <;> simp [Array.make]))

end LeanBlsSimd.PlainWords
namespace LeanBlsSimd.PlainWords
open LeanBlsSimd.Kzg
open scoped EthCryptographySpecs.Bls.Fr
open Kzg.Extender.Kernel Kzg.Extender.Kernel.BytePacking

def sixteenLiteral : blst.blst_fr :=
  ⟨Array.make 4#usize [16#u64,0#u64,0#u64,0#u64] (by rfl)⟩

def sixteenVector : fr8.Fr8 :=
  toArray id (transpose (Vector.replicate 8 (#v[16,0,0,0,0] : Vector UInt64 5)))

theorem sixteen_refines : fr8.Fr8.splat sixteenLiteral = ok sixteenVector := by
  simp only [fr8.Fr8.splat, unpack_refines, bind_tc_ok, FrModel.Simd.splat_limbs_refines]
  congr 1

theorem sixteen_normalized : Normalized sixteenVector := by
  intro j lane
  rw [show (sixteenVector.val[j.val]!)[lane] = (#v[16,0,0,0,0] : Vector UInt64 5)[j] by
    simp [sixteenVector, transpose, getElem!_pos, j.isLt]]
  fin_cases j <;> decide

theorem sixteen_lane (lane : Fin 8) : laneNat sixteenVector lane = 16 := by
  rw [sixteenVector, laneNat_transpose]
  simp [val52]

theorem scalar_mul_inverse (a b : Fr) (ha : a ≠ 0) : a * (a * b).inverse = b.inverse := by
  rw [Fr.inverse_eq_inv, Fr.inverse_eq_inv]
  have key {K : Type} [Field K] (x y : K) (hx : x ≠ 0) : x * (x * y)⁻¹ = y⁻¹ := by
    rw [mul_inv_rev, mul_comm y⁻¹ x⁻¹, ← mul_assoc, mul_inv_cancel₀ hx, one_mul]
  exact key a b ha

theorem sixteen_scale : Fr.ofNat 16 * (Fr.ofNat (2 ^ 260)).inverse =
    (Fr.ofNat (2 ^ 256)).inverse := by
  have hn : (2 : ℕ) ^ 260 = 16 * 2 ^ 256 := by
    calc
      2 ^ 260 = 2 ^ (4 + 256) := rfl
      _ = 2 ^ 4 * 2 ^ 256 := pow_add _ _ _
      _ = 16 * 2 ^ 256 := rfl
  have h : Fr.ofNat (2 ^ 260) = Fr.ofNat 16 * Fr.ofNat (2 ^ 256) := by
    apply Fin.ext
    change (2 ^ 260) % Fr.modulus = (16 % Fr.modulus * ((2 ^ 256) % Fr.modulus)) % Fr.modulus
    rw [Nat.mul_mod_mod, Nat.mod_mul_mod, hn]
  rw [h]
  exact scalar_mul_inverse _ _ (by decide)

theorem sixteen_lt_pow (n : ℕ) (hn : 5 ≤ n) : 16 < 2 ^ n :=
  lt_of_lt_of_le (by decide : 16 < (2 : ℕ) ^ 5) (Nat.pow_le_pow_right (by decide) hn)

theorem convert_refinement (input : Slice blst.blst_fr) (hsize : 8 ≤ input.val.length)
    (hred : ∀ l : Fin 8, FrReduced input.val[l.val]!) :
    ∃ out,
      (do
        let f ← fr8.Fr8.load input 0#usize
        let f1 ← fr8.Fr8.mul f sixteenVector
        let f2 ← fr8.Fr8.normalise f1
        fr8.Fr8.canonical f2) = ok out ∧ Normalized out ∧
      ∀ l : Fin 8, laneNat out l = (frRead input.val[l.val]!).val := by
  obtain ⟨loaded, hload, hn, hv⟩ := load_refinement input 0#usize (by simpa using hsize)
  have hv' (l : Fin 8) : laneNat loaded l = limbs input.val[l.val]!.l.val := by simpa using hv l
  have hproduct (l : Fin 8) : laneNat loaded l * laneNat sixteenVector l < Fr.modulus * 2 ^ 260 := by
    rw [hv', sixteen_lane]
    have h := hred l
    unfold FrReduced at h
    have hp := sixteen_lt_pow 260 (by omega)
    have hm := Fr.modulus_pos
    exact lt_trans (Nat.mul_lt_mul_of_pos_right h (by decide)) (Nat.mul_lt_mul_of_pos_left hp hm)
  obtain ⟨product, hmul, hlazy, hp⟩ := mul_refinement loaded sixteenVector hn sixteen_normalized hproduct
  have hvalues (l : Fin 8) : lazyLaneValue product l = frRead input.val[l.val]! := by
    rw [hp, laneValue, laneValue, hv', sixteen_lane, mul_assoc, sixteen_scale]
    rfl
  obtain ⟨normal, hnorm, hnormal, hnv⟩ := normalise_lazy_refinement product
    (fun l => frRead input.val[l.val]!) ⟨hlazy, hvalues⟩ (by decide) (by decide)
  have hbounded : Bounded normal := by
    refine ⟨hnormal, ?_⟩
    intro l
    have h := (hlazy l).2.1
    rw [← (hnv l).1] at h
    exact_mod_cast h
  obtain ⟨out, hcanonical, hout, houtv⟩ := canonical_refinement normal hbounded
  refine ⟨out, by simp only [hload, hmul, hnorm, hcanonical, bind_tc_ok], hout, ?_⟩
  intro l
  rw [houtv]
  have h := congrArg (fun x : Fr => x.val) (hnv l).2
  simpa only [laneValue, Fr.ofNat] using h

end LeanBlsSimd.PlainWords
namespace LeanBlsSimd.PlainWords

abbrev Chunk := Aeneas.Std.Array blst.blst_fr 8#usize

def chunkPrefix (input : Slice blst.blst_fr) (base cursor : ℕ) (initial : Vector blst.blst_fr 8) :
    Vector blst.blst_fr 8 :=
  Vector.ofFn fun l => if l.val < cursor then input.val[base + l.val]! else initial[l]

theorem chunkPrefix_step (input : Slice blst.blst_fr) (base cursor : ℕ)
    (initial : Vector blst.blst_fr 8) (hc : cursor < 8) :
    (chunkPrefix input base cursor initial).set cursor input.val[base + cursor]! =
      chunkPrefix input base (cursor + 1) initial := by
  ext i hi
  simp only [Vector.getElem_set, chunkPrefix, Vector.getElem_ofFn]
  split <;> split <;> simp_all <;> omega

theorem gather_loop_refines (input : Slice blst.blst_fr) (base count lane : Usize)
    (initial : Vector blst.blst_fr 8) (hc : count.val ≤ 8) (hl : lane.val ≤ count.val)
    (hb : base.val + count.val ≤ input.val.length) :
    fr8.Fr8.plain_words_loop0_loop0 input base count
      (toArray id (chunkPrefix input base.val lane.val initial)) lane =
      ok (toArray id (chunkPrefix input base.val count.val initial)) := by
  induction hn : count.val - lane.val generalizing lane with
  | zero =>
    have he : lane.val = count.val := by omega
    unfold fr8.Fr8.plain_words_loop0_loop0
    rw [loop.eq_1]
    simp only [fr8.Fr8.plain_words_loop0_loop0.body, UScalar.lt_equiv, he, Nat.lt_irrefl, if_false]
  | succ n ih =>
    have hlt : lane.val < count.val := by omega
    have h8 : lane.val < 8 := by omega
    have hi : base.val + lane.val < input.val.length := by omega
    have hsize : input.val.length < 2 ^ UScalarTy.Usize.numBits := by
      have h := input.property
      simp only [Usize.max_def, Usize.numBits_def] at h
      change input.val.length ≤ 2 ^ UScalarTy.Usize.numBits - 1 at h
      have := two_pow_32_le_usize
      omega
    have hadd : base.val + lane.val < 2 ^ UScalarTy.Usize.numBits := by omega
    have hnext : lane.val + 1 < 2 ^ UScalarTy.Usize.numBits := by have := two_pow_32_le_usize; omega
    let next : Usize := UScalar.ofNatCore (lane.val + 1) hnext
    have hv : next.val = lane.val + 1 := rfl
    have hbody : fr8.Fr8.plain_words_loop0_loop0.body input base count
        (toArray id (chunkPrefix input base.val lane.val initial)) lane =
        ok (cont (toArray id (chunkPrefix input base.val next.val initial), next)) := by
      simp only [fr8.Fr8.plain_words_loop0_loop0.body, UScalar.lt_equiv, hlt, if_true]
      rw [add_ok _ _ hadd]
      simp only [bind_tc_ok]
      rw [show Slice.index_usize input (UScalar.ofNatCore _ hadd) = ok input.val[base.val + lane.val] from by
        simp [Slice.index_usize, hi]]
      simp only [bind_tc_ok, update_eq (toArray (n := 8#usize) id (chunkPrefix input base.val lane.val initial)) lane _ h8]
      rw [add_ok _ _ hnext]
      simp only [bind_tc_ok]
      have he : input.val[base.val + lane.val] = input.val[base.val + lane.val]! :=
        (getElem!_pos input.val _ hi).symm
      rw [he]
      erw [set_toArray (n := 8#usize) id (chunkPrefix input base.val lane.val initial) rfl lane input.val[base.val + lane.val]! h8, chunkPrefix_step input base.val lane.val initial h8]
      rfl
    unfold fr8.Fr8.plain_words_loop0_loop0
    change loop (fun p => fr8.Fr8.plain_words_loop0_loop0.body input base count p.1 p.2) _ = _
    rw [loop.eq_1, hbody]
    exact ih next (by omega) (by omega)

def zeroFr : blst.blst_fr := ⟨Array.repeat 4#usize 0#u64⟩

def gathered (input : Slice blst.blst_fr) (base count : ℕ) : Chunk :=
  toArray id (chunkPrefix input base count (Vector.replicate 8 zeroFr))

theorem gather_refines (input : Slice blst.blst_fr) (base count : Usize)
    (hc : count.val ≤ 8) (hb : base.val + count.val ≤ input.val.length) :
    fr8.Fr8.plain_words_loop0_loop0 input base count (Array.repeat 8#usize zeroFr) 0#usize =
      ok (gathered input base.val count.val) := by
  have h := gather_loop_refines input base count 0#usize (Vector.replicate 8 zeroFr) hc (by simp) hb
  simpa [chunkPrefix, gathered, toArray, Array.repeat, Vector.toList_ofFn] using h

theorem gathered_lane (input : Slice blst.blst_fr) (base count : ℕ) (l : Fin 8) :
    (gathered input base count).val[l.val]! =
      if l.val < count then input.val[base + l.val]! else zeroFr := by
  simp [gathered, chunkPrefix, getElem!_pos, l.isLt]

end LeanBlsSimd.PlainWords
namespace LeanBlsSimd.PlainWords
open LeanBlsSimd.Kzg Kzg.Extender.Kernel Kzg.Extender.Kernel.BytePacking

theorem rawWord_packed (v : Vector M512 5) (l : Fin 8) :
    rawWord (wordsMatrix (toArray id (vectorPack v))) l.val =
      toArray toU64 (pack (laneOf v l)) := by
  apply Subtype.ext
  apply List.ext_getElem
  · simp [rawWord, toArray, Array.make]
  · intro i hi hi'
    have hi4 : i < 4 := by simpa [rawWord, Array.make] using hi
    interval_cases i <;>
      simp [rawWord, wordsMatrix, vectorPack, laneOf, toArray, ofArray, Array.make,
        getElem!_pos, l.isLt]

theorem packed_word_value (a : fr8.Fr8) (hn : Normalized a) (l : Fin 8)
    (hb : laneNat a l < 2 ^ 256) :
    limbs (rawWord (wordsMatrix (toArray id (vectorPack (ofArray id a)))) l.val).val = laneNat a l := by
  rw [rawWord_packed, ← limbs_ofArray, ofArray_toArray_ofU64]
  have h := packed_store_value a hn l hb
  simpa only [getElem_store] using h

theorem pack_append_refinement (a : fr8.Fr8) (hn : Normalized a)
    (hb : ∀ l, laneNat a l < 2 ^ 256)
    (words : alloc.vec.Vec Word) (count : Usize) (hc : count.val ≤ 8)
    (hroom : words.val.length + count.val ≤ Usize.max) :
    ∃ out,
      (do let packed ← fr8.u256x8.U256x8.from_limbs a
          fr8.u256x8.U256x8.push_words packed words count) = ok out ∧
      out.val.length = words.val.length + count.val ∧
      out.val.map (fun w => limbs w.val) = words.val.map (fun w => limbs w.val) ++
        ((List.finRange count.val).map (fun l => laneNat a ⟨l.val, by omega⟩)) := by
  have hnormal : ∀ j : Fin 5, ∀ l : Fin 8, (ofArray id a)[j][l].toNat < 2 ^ 52 := by
    intro j l
    simpa [getElem!_pos, j.isLt, a.property] using hn j l
  have hpack := vectorPack_refines (ofArray id a) hnormal
  have he : toArray (n := 5#usize) id (ofArray id a) = a :=
    toArray_ofArray (f := @id M512) (g := @id M512) (fun _ => rfl) a rfl rfl
  erw [he] at hpack
  obtain ⟨out, hout, hval⟩ := push_words_refines (toArray id (vectorPack (ofArray id a))) words count hc hroom
  refine ⟨out, by simp only [hpack, hout, bind_tc_ok], ?_, ?_⟩
  · simp [hval]
  · rw [hval, List.map_append, List.map_map]
    congr 1
    rw [← List.map_coe_finRange_eq_range, List.map_map]
    apply List.map_congr_left
    intro l _
    exact packed_word_value a hn ⟨l.val, by omega⟩ (hb _)

end LeanBlsSimd.PlainWords
namespace LeanBlsSimd.PlainWords
open LeanBlsSimd.Kzg Kzg.Extender.Kernel Kzg.Extender.Kernel.BytePacking

def convertBatch (input : Slice blst.blst_fr) : Result fr8.Fr8 := do
  let f ← fr8.Fr8.load input 0#usize
  let f1 ← fr8.Fr8.mul f sixteenVector
  let f2 ← fr8.Fr8.normalise f1
  fr8.Fr8.canonical f2

def packWords (plain : fr8.Fr8) (words : alloc.vec.Vec Word) (count : Usize) : Result (alloc.vec.Vec Word) := do
  let packed ← fr8.u256x8.U256x8.from_limbs plain
  fr8.u256x8.U256x8.push_words packed words count

def plainBatch (input : Slice blst.blst_fr) (base count : Usize) (words : alloc.vec.Vec Word) :
    Result (alloc.vec.Vec Word) := do
  let chunk ← fr8.Fr8.plain_words_loop0_loop0 input base count (Array.repeat 8#usize zeroFr) 0#usize
  let plain ← convertBatch (Array.to_slice chunk)
  packWords plain words count

def scalarValues (input : Slice blst.blst_fr) (base count : ℕ) : List ℕ :=
  (List.range' base count).map (fun i => (frRead input.val[i]!).val)

theorem gathered_reduced (input : Slice blst.blst_fr) (base count : ℕ)
    (hb : base + count ≤ input.val.length) (hr : ∀ x ∈ input.val, FrReduced x) (l : Fin 8) :
    FrReduced (gathered input base count).val[l.val]! := by
  rw [gathered_lane]
  split
  · rename_i hl
    apply hr
    have hi : base + l.val < input.val.length := by omega
    rw [getElem!_pos input.val _ hi]
    exact List.getElem_mem hi
  · change 0 < Fr.modulus
    exact Fr.modulus_pos

theorem gathered_values (input : Slice blst.blst_fr) (base count : ℕ) (hc : count ≤ 8)
    (f : blst.blst_fr → ℕ) :
    (List.finRange count).map (fun l => f (gathered input base count).val[l.val]!) =
      (List.range' base count).map (fun i => f input.val[i]!) := by
  have hidx : List.range' base count = (List.range count).map (base + ·) := by
    simpa only [List.range_eq_range'] using (List.map_add_range' (a := base) 0 count 1).symm
  rw [hidx, ← List.map_coe_finRange_eq_range, List.map_map, List.map_map]
  apply List.map_congr_left
  intro l _
  have he := gathered_lane input base count (⟨l.val, by omega⟩ : Fin 8)
  simp only [l.isLt, if_true] at he
  exact congrArg f he

theorem batch_refines (input : Slice blst.blst_fr) (base count : Usize) (words : alloc.vec.Vec Word)
    (hc : count.val ≤ 8) (hb : base.val + count.val ≤ input.val.length)
    (hr : ∀ x ∈ input.val, FrReduced x)
    (hroom : words.val.length + count.val ≤ Usize.max) :
    ∃ out, plainBatch input base count words = ok out ∧
      out.val.length = words.val.length + count.val ∧
      out.val.map (fun w => limbs w.val) = words.val.map (fun w => limbs w.val) ++
        scalarValues input base.val count.val := by
  let chunk := gathered input base.val count.val
  have hred (l : Fin 8) : FrReduced (Array.to_slice chunk).val[l.val]! :=
    gathered_reduced input base.val count.val hb hr l
  obtain ⟨canonical, hconvert, hn, hv⟩ := convert_refinement (Array.to_slice chunk)
    (by simp [Array.to_slice, chunk, gathered, toArray]) hred
  have hsmall (l : Fin 8) : laneNat canonical l < 2 ^ 256 := by
    rw [hv]
    exact lt_trans (frRead _).isLt (by decide)
  obtain ⟨out, hout, hlen, hval⟩ := pack_append_refinement canonical hn hsmall words count hc hroom
  refine ⟨out, ?_, hlen, ?_⟩
  · unfold plainBatch
    rw [gather_refines input base count hc hb]
    simp only [bind_tc_ok]
    change (convertBatch (Array.to_slice chunk) >>= fun a => packWords a words count) = _
    change convertBatch (Array.to_slice chunk) = ok canonical at hconvert
    rw [hconvert]
    exact hout
  · rw [hval]
    congr 1
    calc
      _ = (List.finRange count.val).map (fun l => (frRead chunk.val[l.val]!).val) := by
        apply List.map_congr_left
        intro l _
        exact hv ⟨l.val, by omega⟩
      _ = _ := gathered_values input base.val count.val hc (fun x => (frRead x).val)

end LeanBlsSimd.PlainWords
namespace LeanBlsSimd.PlainWords
open LeanBlsSimd.Kzg

theorem scalarValues_append (input : Slice blst.blst_fr) (base n m : ℕ) :
    scalarValues input base n ++ scalarValues input (base + n) m = scalarValues input base (n + m) := by
  unfold scalarValues
  rw [← List.map_append, List.range'_append_1]

theorem plain_loop_refines (input : Slice blst.blst_fr) (words : alloc.vec.Vec Word) (base : Usize)
    (hb : base.val ≤ input.val.length) (hr : ∀ x ∈ input.val, FrReduced x)
    (hroom : words.val.length + (input.val.length - base.val) ≤ Usize.max) :
    ∃ out, fr8.Fr8.plain_words_loop0 input words sixteenVector base = ok out ∧
      out.val.length = words.val.length + (input.val.length - base.val) ∧
      out.val.map (fun w => limbs w.val) = words.val.map (fun w => limbs w.val) ++
        scalarValues input base.val (input.val.length - base.val) := by
  generalize hrem : input.val.length - base.val = remaining
  induction remaining using Nat.strong_induction_on generalizing words base with
  | h remaining ih =>
    by_cases hlt : base.val < input.val.length
    · have hsize : input.val.length < 2 ^ UScalarTy.Usize.numBits := by
        have h := input.property
        simp only [Usize.max_def, Usize.numBits_def] at h
        change input.val.length ≤ 2 ^ UScalarTy.Usize.numBits - 1 at h
        have := two_pow_32_le_usize
        omega
      let countNat := min 8 (input.val.length - base.val)
      have hc : countNat ≤ 8 := Nat.min_le_left _ _
      have hcpos : 0 < countNat := by dsimp [countNat]; omega
      have hcb : base.val + countNat ≤ input.val.length := by dsimp [countNat]; omega
      let count : Usize := UScalar.ofNatCore countNat (by omega)
      have hcv : count.val = countNat := rfl
      have hcount : (do
          let rest ← Slice.len input - base
          if rest < fr8.LANES then Slice.len input - base else ok fr8.LANES) = ok count := by
        rw [sub_ok _ _ hb]
        simp only [bind_tc_ok, fr8.LANES, UScalar.lt_equiv, UScalar.ofNatCore_val_eq, Slice.len, Usize.ofNatCore_val_eq]
        split
        · congr 1
          apply UScalar.eq_of_val_eq
          simp only [UScalar.ofNatCore_val_eq]
          omega
        · congr 1
          apply UScalar.eq_of_val_eq
          simp only [UScalar.ofNatCore_val_eq]
          omega
      obtain ⟨nextWords, hbatch, hlen, hval⟩ := batch_refines input base count words
        (by omega) (by omega) hr (by omega)
      have hadd : base.val + count.val < 2 ^ UScalarTy.Usize.numBits := by omega
      let next : Usize := UScalar.ofNatCore (base.val + count.val) hadd
      have hnv : next.val = base.val + count.val := rfl
      have hbody : fr8.Fr8.plain_words_loop0.body input sixteenVector words base =
          ok (cont (nextWords,next)) := by
        simp only [fr8.Fr8.plain_words_loop0.body, UScalar.lt_equiv, Slice.len, Usize.ofNatCore_val_eq, hlt, if_true]
        simp only [UScalar.lt_equiv, Slice.len] at hcount
        rw [← bind_assoc_eq, hcount]
        simp only [bind_tc_ok, lift]
        unfold plainBatch convertBatch packWords zeroFr at hbatch
        simp only [bind_assoc_eq] at hbatch
        rw [← bind_assoc_eq, ← bind_assoc_eq, ← bind_assoc_eq, ← bind_assoc_eq,
          ← bind_assoc_eq, ← bind_assoc_eq]
        rw [← bind_assoc_eq, ← bind_assoc_eq, ← bind_assoc_eq, ← bind_assoc_eq,
          ← bind_assoc_eq] at hbatch
        rw [hbatch]
        simp only [bind_tc_ok]
        rw [add_ok _ _ hadd]
        rfl
      obtain ⟨out, hout, houtlen, houtval⟩ := ih (input.val.length - next.val) (by omega)
        nextWords next (by omega) (by omega) rfl
      refine ⟨out, ?_, by omega, ?_⟩
      · unfold fr8.Fr8.plain_words_loop0
        change loop (fun p => fr8.Fr8.plain_words_loop0.body input sixteenVector p.1 p.2) _ = _
        rw [loop.eq_1, hbody]
        exact hout
      · rw [houtval, hval, List.append_assoc, hnv, scalarValues_append]
        congr 2
        omega
    · have he : base.val = input.val.length := by omega
      refine ⟨words, ?_, by omega, ?_⟩
      · unfold fr8.Fr8.plain_words_loop0
        rw [loop.eq_1]
        simp only [fr8.Fr8.plain_words_loop0.body, UScalar.lt_equiv, Slice.len, Usize.ofNatCore_val_eq, hlt, if_false]
      · have hz : remaining = 0 := by omega
        simp [hz, scalarValues]

end LeanBlsSimd.PlainWords
namespace LeanBlsSimd.PlainWords
open LeanBlsSimd.Kzg

theorem scalarValues_all (input : Slice blst.blst_fr) :
    scalarValues input 0 input.val.length = input.val.map (fun x => (frRead x).val) := by
  unfold scalarValues
  rw [← List.range_eq_range']
  apply List.ext_getElem
  · simp
  · intro i hi hi'
    have hib : i < input.val.length := by simpa using hi
    simp [hib]

theorem clone_word (word : Word) :
    core.array.CloneArray.clone core.clone.CloneU64 word = ok word := by
  obtain ⟨out, h, he⟩ := WP.spec_imp_exists
    (core.array.CloneArray.clone_spec core.clone.CloneU64 word (by intro x hx; rfl))
  simpa only [he] using h

theorem plain_words_correct (input : Slice blst.blst_fr) (words : alloc.vec.Vec Word)
    (hr : ∀ x ∈ input.val, FrReduced x) :
    ∃ out, fr8.Fr8.plain_words input words = ok out ∧ out.val.length = input.val.length ∧
      out.val.map (fun word => limbs word.val) = input.val.map (fun x => (frRead x).val) := by
  obtain ⟨empty, he, hev⟩ := WP.spec_imp_exists (alloc.vec.Vec.resize_spec
    (core.clone.CloneArray 4#usize core.clone.CloneU64) words 0#usize (Array.repeat 4#usize 0#u64)
    (clone_word _))
  have hempty : empty.val = [] := by simpa [List.resize] using hev
  obtain ⟨out, hout, hlen, hval⟩ := plain_loop_refines input empty 0#usize (by simp) hr
    (by simpa [hempty] using input.property)
  refine ⟨out, ?_, by simpa [hempty] using hlen, ?_⟩
  · simp only [fr8.Fr8.plain_words]
    change (do let sixteen ← fr8.Fr8.splat sixteenLiteral
               let empty ← alloc.vec.Vec.resize (core.clone.CloneArray 4#usize core.clone.CloneU64)
                 words 0#usize (Array.repeat 4#usize 0#u64)
               fr8.Fr8.plain_words_loop0 input empty sixteen 0#usize) = _
    simp only [sixteen_refines, he, hout, bind_tc_ok]
  · simpa only [hempty, List.map_nil, List.nil_append, UScalar.ofNatCore_val_eq,
      Nat.sub_zero, scalarValues_all] using hval

theorem plain_words_lanes (input : Slice blst.blst_fr) (words : alloc.vec.Vec Word)
    (hr : ∀ x ∈ input.val, FrReduced x) :
    ∃ out, fr8.Fr8.plain_words input words = ok out ∧ out.val.length = input.val.length ∧
      ∀ i, i < input.val.length → limbs out.val[i]!.val = (frRead input.val[i]!).val := by
  obtain ⟨out, hout, hlen, hv⟩ := plain_words_correct input words hr
  refine ⟨out, hout, hlen, ?_⟩
  intro i hi
  have h := congrArg (fun xs : List ℕ => xs[i]!) hv
  simpa [getElem!_pos, hi, hlen] using h

end LeanBlsSimd.PlainWords

namespace LeanBlsSimd.PlainWords
open LeanBlsSimd.Kzg

theorem plain_words_encoded (input : Slice blst.blst_fr) (words : alloc.vec.Vec Word)
    (values : List Fr) (hinput : input.val = values.map frEncode) :
    ∃ out, fr8.Fr8.plain_words input words = ok out ∧ out.val.length = values.length ∧
      out.val.map (fun word => limbs word.val) = values.map (fun x => x.val) := by
  have hr : ∀ x ∈ input.val, FrReduced x := by
    intro x hx
    rw [hinput] at hx
    obtain ⟨v, _, rfl⟩ := List.mem_map.mp hx
    exact frEncode_reduced v
  obtain ⟨out, hout, hlen, hv⟩ := plain_words_correct input words hr
  refine ⟨out, hout, by simpa [hinput] using hlen, ?_⟩
  simpa only [hinput, List.map_map, Function.comp_def, frRead_frEncode] using hv

end LeanBlsSimd.PlainWords
