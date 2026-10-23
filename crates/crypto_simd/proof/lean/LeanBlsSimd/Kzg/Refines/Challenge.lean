import LeanBlsSimd.Kzg.Fr.ByteEncode
import LeanBlsSimd.Kzg.ShaContracts
import LeanBlsSimd.Kzg.ScalarContracts
import LeanBlsSimd.Kzg.Model

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

set_option maxHeartbeats 4000000

private def challengeByte (value : U64) (shift : Nat) : U8 :=
  ⟨BitVec.ofNat 8 (value.val >>> shift)⟩

private def challengeBE (value : U64) (n : Nat := 8) : List U8 :=
  (List.range n).reverse.map (fun k => challengeByte value (8*k))

private theorem challengeBE_length (value : U64) (n : Nat) :
    (challengeBE value n).length = n := by simp [challengeBE]

private theorem challengeBE_succ (value : U64) (n : Nat) :
    challengeBE value (n+1) = challengeByte value (8*n) :: challengeBE value n := by
  simp [challengeBE, List.range_succ]

private theorem challenge_bytes_append (xs ys : List U8) :
    bytes (xs ++ ys) = bytes xs ++ bytes ys := by
  apply ByteArray.ext
  simp [bytes, List.map_append]

private theorem challengeBE_bytes (value : U64) :
    bytes (challengeBE value) = intToBytesBE value.val 8 := by
  apply ByteArray.ext
  apply _root_.Array.toList_inj.mp
  simp only [bytes, intToBytesBE, List.toList_toArray, _root_.Array.toList_ofFn]
  apply List.ext_getElem (by simp [challengeBE])
  intro i hi hi'
  have hil : i < 8 := by simpa [challengeBE] using hi
  simp only [List.getElem_map, challengeBE, List.getElem_map, List.getElem_reverse,
    List.length_range, List.getElem_range, List.getElem_ofFn, challengeByte]
  apply UInt8.toNat_inj.mp
  change (value.val >>> (8 * (8 - 1 - i))) % 256 =
    ((value.val >>> ((8 - 1 - i) * 8)) &&& 255) % 256
  rw [Nat.mul_comm 8, show (255 : Nat) = 2^8 - 1 from rfl,
    Nat.and_two_pow_sub_one_eq_mod]
  simp

private theorem challenge_add (a b : Usize)
    (hb : a.val + b.val < 2 ^ UScalarTy.Usize.numBits) :
    a + b = ok (UScalar.ofNatCore (a.val + b.val) hb) := by
  show UScalar.tryMk .Usize (a.val + b.val) = _
  have hb' : a.val + b.val < 2 ^ System.Platform.numBits := hb
  simp [UScalar.tryMk, UScalar.tryMkOpt, hb', Result.ofOption]

private theorem challenge_cast (value : Usize) :
    (UScalar.cast .U64 value).val = value.val := by
  rw [UScalar.cast_val_eq]
  apply Nat.mod_eq_of_lt
  have hb := value.hBounds
  rcases System.Platform.numBits_eq with h | h <;>
    simp [UScalarTy.numBits, h] at hb ⊢ <;> omega

private def challengeRow (ci : Slice Usize) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (ps : Slice (Aeneas.Std.Array U8 48#usize)) (k : Nat) : List U8 :=
  challengeBE (UScalar.cast .U64 ci.val[k]!) ++ challengeBE indices.val[k]! ++
    cells.val[k]!.val ++ ps.val[k]!.val

private theorem challengeRow_length (ci : Slice Usize) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (ps : Slice (Aeneas.Std.Array U8 48#usize)) (k : Nat) :
    (challengeRow ci indices cells ps k).length = 2112 := by
  simp [challengeRow, challengeBE_length]

private def challengeHeader (u n : Usize) : List U8 :=
  challenge.DOMAIN.val ++ challengeBE (UScalar.cast .U64 FIELD_ELEMENTS_PER_BLOB) ++
    challengeBE (UScalar.cast .U64 FIELD_ELEMENTS_PER_CELL) ++
    challengeBE (UScalar.cast .U64 u) ++ challengeBE (UScalar.cast .U64 n)

private theorem challengeHeader_length (u n : Usize) :
    (challengeHeader u n).length = 48 := by
  simp [challengeHeader, challengeBE_length, challenge.DOMAIN.property]

private theorem challengeHeader_bytes (u n : Usize) :
    bytes (challengeHeader u n) = Kzg.Constants.RANDOM_CHALLENGE_KZG_CELL_BATCH_DOMAIN ++
      intToBytesBE 4096 8 ++ intToBytesBE 64 8 ++ intToBytesBE u.val 8 ++ intToBytesBE n.val 8 := by
  have hdomain : bytes challenge.DOMAIN.val = Kzg.Constants.RANDOM_CHALLENGE_KZG_CELL_BATCH_DOMAIN := by
    decide +kernel
  simp only [challengeHeader, challenge_bytes_append, challengeBE_bytes, challenge_cast,
    FIELD_ELEMENTS_PER_BLOB, FIELD_ELEMENTS_PER_CELL, UScalar.ofNatCore_val_eq, hdomain]

private theorem challenge_fold_bytes {α : Type} (xs : List α) (f : α → List U8)
    (b : ByteArray) :
    xs.foldl (fun b x => b ++ bytes (f x)) b = b ++ bytes (xs.flatMap f) := by
  induction xs generalizing b with
  | nil => exact (ByteArray.append_empty (b := b)).symm
  | cons x xs ih =>
    simp only [List.foldl_cons, ih, List.flatMap_cons, challenge_bytes_append,
      ByteArray.append_assoc]

private theorem challenge_fold_congr {α β : Type} (xs : List α) (f g : β → α → β)
    (b : β) (h : ∀ x ∈ xs, ∀ b, f b x = g b x) : xs.foldl f b = xs.foldl g b := by
  induction xs generalizing b with
  | nil => rfl
  | cons x xs ih =>
    rw [List.foldl_cons, List.foldl_cons, h x (by simp)]
    exact ih _ (fun y hy => h y (by simp [hy]))

private theorem challenge_map_get {α β : Type} [Inhabited α] [Inhabited β]
    (xs : List α) (f : α → β) (k : Nat) (hk : k < xs.length) :
    (xs.map f).toArray[k]! = f xs[k]! := by
  simp [getElem!_pos, hk]

private theorem challenge_model_bytes
    (unique : Slice (Aeneas.Std.Array U8 48#usize)) (ci : Slice Usize) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (ps : Slice (Aeneas.Std.Array U8 48#usize))
    (hlen : ci.val.length = indices.val.length ∧ cells.val.length = indices.val.length ∧
      ps.val.length = indices.val.length) :
    bytes (challengeHeader (Slice.len unique) (Slice.len indices) ++
      unique.val.flatMap (·.val) ++
      (List.range indices.val.length).flatMap (challengeRow ci indices cells ps)) =
      Model.challengePreimage (unique.val.map arrayBytes).toArray
        (ci.val.map (·.val)).toArray (indices.val.map (·.val)).toArray
        (cells.val.map arrayBytes).toArray (ps.val.map arrayBytes).toArray := by
  rw [challenge_bytes_append, challenge_bytes_append]
  rw [← challenge_fold_bytes unique.val (fun a => a.val)]
  rw [← challenge_fold_bytes (List.range indices.val.length) (challengeRow ci indices cells ps)]
  unfold Model.challengePreimage
  simp only [List.foldl_toArray', List.size_toArray, List.length_map,
    ← _root_.Array.foldl_toList, _root_.Array.toList_range, List.foldl_map]
  rw [challengeHeader_bytes]
  simp only [Slice.len_val, Slice.length]
  apply challenge_fold_congr
  intro k hk b
  have hk' : k < indices.val.length := List.mem_range.mp hk
  have hci : k < ci.val.length := by omega
  have hc : k < cells.val.length := by omega
  have hp : k < ps.val.length := by omega
  simp only [challengeRow, challenge_bytes_append, challengeBE_bytes, challenge_cast,
    challenge_map_get ci.val (fun x => x.val) k hci,
    challenge_map_get indices.val (fun x => x.val) k hk',
    challenge_map_get cells.val arrayBytes k hc, challenge_map_get ps.val arrayBytes k hp,
    arrayBytes, ByteArray.append_assoc]


private theorem challenge_to_be_bytes (value : U64) :
    (core.num.U64.to_be_bytes value).val = challengeBE value := by
  simp [core.num.U64.to_be_bytes, BitVec.toBEBytes, BitVec.toLEBytes,
    challengeBE, List.range_succ, challengeByte]
  repeat' constructor
  all_goals
    apply BitVec.eq_of_toNat_eq
    simp [BitVec.toNat_setWidth, BitVec.toNat_ushiftRight,
      Nat.shiftRight_eq_div_pow]
    omega

private theorem challenge_extensions_loop0_eq
    (h : ShaPathCorrect sha256.extensions.Sha256.new sha256.extensions.Sha256.update
      sha256.extensions.Sha256.finish)
    (self : sha256.extensions.Sha256) (pre : List U8)
    (hself : ShaRep sha256.extensions.Sha256.update sha256.extensions.Sha256.finish self pre)
    (unique : Slice (Aeneas.Std.Array U8 48#usize)) (i : Usize)
    (hi : i.val ≤ unique.val.length) :
    ∃ next, challenge.challenge_in_parts_loop0 unique self i = ok next ∧
      ShaRep sha256.extensions.Sha256.update sha256.extensions.Sha256.finish next
        (pre ++ (unique.val.drop i.val).flatMap (·.val)) := by
  induction hn : unique.val.length - i.val generalizing self pre i with
  | zero =>
    have he : i.val = unique.val.length := by omega
    have hstop : ¬ i < Slice.len unique := by simp [he]
    refine ⟨self, ?_, by simpa [he] using hself⟩
    rw [challenge.challenge_in_parts_loop0, loop.eq_1]
    simp only [challenge.challenge_in_parts_loop0.body, hstop, if_false]
  | succ n ih =>
    have hlt : i.val < unique.val.length := by omega
    have htest : i < Slice.len unique := by simpa using hlt
    have hin : i.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
      have := (Slice.len unique).hBounds
      simp only [Slice.len_val, Slice.length] at this
      omega
    let i' : Usize := UScalar.ofNatCore (i.val + 1) hin
    have hi' : i'.val = i.val + 1 := UScalar.ofNatCore_val_eq _
    have hadd : i + 1#usize = ok i' := challenge_add i 1#usize hin
    let a := unique.val[i.val]'hlt
    have hindex : Slice.index_usize unique i = ok a := by simp [Slice.index_usize, hlt, a]
    obtain ⟨s, hup, hs⟩ := h.update_spec self pre (Array.to_slice a) hself
    obtain ⟨next, hloop, hrep⟩ := ih s (pre ++ a.val) hs i' (by omega) (by omega)
    refine ⟨next, ?_, ?_⟩
    · rw [challenge.challenge_in_parts_loop0, loop.eq_1]
      simp only [challenge.challenge_in_parts_loop0.body, htest, if_true, hindex,
        bind_tc_ok, lift, hup, hadd]
      exact hloop
    · rw [List.drop_eq_getElem_cons hlt]
      simpa only [List.flatMap_cons, hi', List.append_assoc] using hrep

private theorem challenge_extensions_loop1_eq
    (h : ShaPathCorrect sha256.extensions.Sha256.new sha256.extensions.Sha256.update
      sha256.extensions.Sha256.finish)
    (self : sha256.extensions.Sha256) (pre : List U8)
    (hself : ShaRep sha256.extensions.Sha256.update sha256.extensions.Sha256.finish self pre)
    (ci : Slice Usize) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (ps : Slice (Aeneas.Std.Array U8 48#usize)) (k : Usize)
    (hlen : ci.val.length = indices.val.length ∧ cells.val.length = indices.val.length ∧
      ps.val.length = indices.val.length)
    (hk : k.val ≤ indices.val.length) :
    ∃ next, challenge.challenge_in_parts_loop1 ci indices cells ps self k = ok next ∧
      ShaRep sha256.extensions.Sha256.update sha256.extensions.Sha256.finish next
        (pre ++ ((List.range indices.val.length).drop k.val).flatMap
          (challengeRow ci indices cells ps)) := by
  induction hn : indices.val.length - k.val generalizing self pre k with
  | zero =>
    have he : k.val = indices.val.length := by omega
    have hstop : ¬ k < Slice.len indices := by simp [he]
    refine ⟨self, ?_, by simpa [he] using hself⟩
    rw [challenge.challenge_in_parts_loop1, loop.eq_1]
    simp only [challenge.challenge_in_parts_loop1.body, hstop, if_false]
  | succ n ih =>
    have hlt : k.val < indices.val.length := by omega
    have htest : k < Slice.len indices := by simpa using hlt
    have hkci : k.val < ci.val.length := by omega
    have hkc : k.val < cells.val.length := by omega
    have hkp : k.val < ps.val.length := by omega
    have hindex0 : Slice.index_usize ci k = ok ci.val[k.val]! := by
      simp [Slice.index_usize, hkci]
    have hindex1 : Slice.index_usize indices k = ok indices.val[k.val]! := by
      simp [Slice.index_usize, hlt]
    have hindex2 : Slice.index_usize cells k = ok cells.val[k.val]! := by
      simp [Slice.index_usize, hkc]
    have hindex3 : Slice.index_usize ps k = ok ps.val[k.val]! := by
      simp [Slice.index_usize, hkp]
    obtain ⟨s1, hup1, hs1⟩ := h.update_spec self pre
      (Array.to_slice (core.num.U64.to_be_bytes (UScalar.cast .U64 ci.val[k.val]!))) hself
    obtain ⟨s2, hup2, hs2⟩ := h.update_spec s1 _
      (Array.to_slice (core.num.U64.to_be_bytes indices.val[k.val]!)) hs1
    obtain ⟨s3, hup3, hs3⟩ := h.update_spec s2 _ (Array.to_slice cells.val[k.val]!) hs2
    obtain ⟨s4, hup4, hs4⟩ := h.update_spec s3 _ (Array.to_slice ps.val[k.val]!) hs3
    have hs : ShaRep sha256.extensions.Sha256.update sha256.extensions.Sha256.finish s4
        (pre ++ challengeRow ci indices cells ps k.val) := by
      simpa only [Array.to_slice, challenge_to_be_bytes, challengeRow, List.append_assoc] using hs4
    have hin : k.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
      have := (Slice.len indices).hBounds
      simp only [Slice.len_val, Slice.length] at this
      omega
    let k' : Usize := UScalar.ofNatCore (k.val + 1) hin
    have hk' : k'.val = k.val + 1 := UScalar.ofNatCore_val_eq _
    have hadd : k + 1#usize = ok k' := challenge_add k 1#usize hin
    obtain ⟨next, hloop, hrep⟩ := ih s4 (pre ++ challengeRow ci indices cells ps k.val)
      hs k' (by omega) (by omega)
    refine ⟨next, ?_, ?_⟩
    · rw [challenge.challenge_in_parts_loop1, loop.eq_1]
      simp only [challenge.challenge_in_parts_loop1.body, htest, if_true,
        hindex0, hindex1, hindex2, hindex3, bind_tc_ok, lift, hup1, hup2,
        hup3, hup4, hadd]
      exact hloop
    · rw [List.drop_eq_getElem_cons (by simp [hlt])]
      simpa only [List.flatMap_cons, List.getElem_range, hk', List.append_assoc] using hrep

theorem challenge_refinement (hsha : ShaCorrect)
    (unique : Slice (Aeneas.Std.Array U8 48#usize))
    (ci : Slice Usize) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (ps : Slice (Aeneas.Std.Array U8 48#usize))
    (hlen : ci.val.length = indices.val.length ∧ cells.val.length = indices.val.length ∧
      ps.val.length = indices.val.length) :
    challenge.challenge_in_parts unique ci indices cells ps =
      ok (frEncode (Fr.hashToBlsField (Model.challengePreimage
        (unique.val.map arrayBytes).toArray (ci.val.map (·.val)).toArray
        (indices.val.map (·.val)).toArray (cells.val.map arrayBytes).toArray
        (ps.val.map arrayBytes).toArray))) := by
  have h := hsha.extensions
  obtain ⟨s0, hnew, hs0⟩ := h.new_spec
  obtain ⟨s1, hup1, hs1⟩ := h.update_spec s0 [] (Array.to_slice challenge.DOMAIN) hs0
  obtain ⟨s2, hup2, hs2⟩ := h.update_spec s1 _
    (Array.to_slice (core.num.U64.to_be_bytes (UScalar.cast .U64 FIELD_ELEMENTS_PER_BLOB))) hs1
  obtain ⟨s3, hup3, hs3⟩ := h.update_spec s2 _
    (Array.to_slice (core.num.U64.to_be_bytes (UScalar.cast .U64 FIELD_ELEMENTS_PER_CELL))) hs2
  obtain ⟨s4, hup4, hs4⟩ := h.update_spec s3 _
    (Array.to_slice (core.num.U64.to_be_bytes (UScalar.cast .U64 (Slice.len unique)))) hs3
  obtain ⟨s5, hup5, hs5⟩ := h.update_spec s4 _
    (Array.to_slice (core.num.U64.to_be_bytes (UScalar.cast .U64 (Slice.len indices)))) hs4
  have hs : ShaRep sha256.extensions.Sha256.update sha256.extensions.Sha256.finish s5
      (challengeHeader (Slice.len unique) (Slice.len indices)) := by
    simpa only [Array.to_slice, List.nil_append, challenge_to_be_bytes, challengeHeader] using hs5
  obtain ⟨s6, hl0, hs6⟩ := challenge_extensions_loop0_eq h s5 _ hs unique 0#usize (by simp)
  obtain ⟨s7, hl1, hs7⟩ := challenge_extensions_loop1_eq h s6 _ hs6 ci indices cells ps
    0#usize hlen (by simp)
  obtain ⟨digest, hfinish, hdigest⟩ := h.finish_spec s7 _ hs7
  simp only [UScalar.ofNatCore_val_eq, List.drop_zero] at hdigest
  rw [challenge_model_bytes unique ci indices cells ps hlen] at hdigest
  unfold challenge.challenge_in_parts
  simp only [hnew, bind_tc_ok, lift, hup1, hup2, hup3, hup4, hup5, hl0, hl1, hfinish]
  rw [FrScalar.fr_from_bytes_reduced_refines, hdigest]
  rfl

private theorem challenge_portable_loop0_eq
    (h : ShaPathCorrect sha256.portable.Sha256.new sha256.portable.Sha256.update
      sha256.portable.Sha256.finish)
    (self : sha256.portable.Sha256) (pre : List U8)
    (hself : ShaRep sha256.portable.Sha256.update sha256.portable.Sha256.finish self pre)
    (unique : Slice (Aeneas.Std.Array U8 48#usize)) (i : Usize)
    (hi : i.val ≤ unique.val.length) :
    ∃ next, challenge.challenge_in_parts_portable_loop0 unique self i = ok next ∧
      ShaRep sha256.portable.Sha256.update sha256.portable.Sha256.finish next
        (pre ++ (unique.val.drop i.val).flatMap (·.val)) := by
  induction hn : unique.val.length - i.val generalizing self pre i with
  | zero =>
    have he : i.val = unique.val.length := by omega
    have hstop : ¬ i < Slice.len unique := by simp [he]
    refine ⟨self, ?_, by simpa [he] using hself⟩
    rw [challenge.challenge_in_parts_portable_loop0, loop.eq_1]
    simp only [challenge.challenge_in_parts_portable_loop0.body, hstop, if_false]
  | succ n ih =>
    have hlt : i.val < unique.val.length := by omega
    have htest : i < Slice.len unique := by simpa using hlt
    have hin : i.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
      have := (Slice.len unique).hBounds
      simp only [Slice.len_val, Slice.length] at this
      omega
    let i' : Usize := UScalar.ofNatCore (i.val + 1) hin
    have hi' : i'.val = i.val + 1 := UScalar.ofNatCore_val_eq _
    have hadd : i + 1#usize = ok i' := challenge_add i 1#usize hin
    let a := unique.val[i.val]'hlt
    have hindex : Slice.index_usize unique i = ok a := by simp [Slice.index_usize, hlt, a]
    obtain ⟨s, hup, hs⟩ := h.update_spec self pre (Array.to_slice a) hself
    obtain ⟨next, hloop, hrep⟩ := ih s (pre ++ a.val) hs i' (by omega) (by omega)
    refine ⟨next, ?_, ?_⟩
    · rw [challenge.challenge_in_parts_portable_loop0, loop.eq_1]
      simp only [challenge.challenge_in_parts_portable_loop0.body, htest, if_true, hindex,
        bind_tc_ok, lift, hup, hadd]
      exact hloop
    · rw [List.drop_eq_getElem_cons hlt]
      simpa only [List.flatMap_cons, hi', List.append_assoc] using hrep

private theorem challenge_portable_loop1_eq
    (h : ShaPathCorrect sha256.portable.Sha256.new sha256.portable.Sha256.update
      sha256.portable.Sha256.finish)
    (self : sha256.portable.Sha256) (pre : List U8)
    (hself : ShaRep sha256.portable.Sha256.update sha256.portable.Sha256.finish self pre)
    (ci : Slice Usize) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (ps : Slice (Aeneas.Std.Array U8 48#usize)) (k : Usize)
    (hlen : ci.val.length = indices.val.length ∧ cells.val.length = indices.val.length ∧
      ps.val.length = indices.val.length)
    (hk : k.val ≤ indices.val.length) :
    ∃ next, challenge.challenge_in_parts_portable_loop1 ci indices cells ps self k = ok next ∧
      ShaRep sha256.portable.Sha256.update sha256.portable.Sha256.finish next
        (pre ++ ((List.range indices.val.length).drop k.val).flatMap
          (challengeRow ci indices cells ps)) := by
  induction hn : indices.val.length - k.val generalizing self pre k with
  | zero =>
    have he : k.val = indices.val.length := by omega
    have hstop : ¬ k < Slice.len indices := by simp [he]
    refine ⟨self, ?_, by simpa [he] using hself⟩
    rw [challenge.challenge_in_parts_portable_loop1, loop.eq_1]
    simp only [challenge.challenge_in_parts_portable_loop1.body, hstop, if_false]
  | succ n ih =>
    have hlt : k.val < indices.val.length := by omega
    have htest : k < Slice.len indices := by simpa using hlt
    have hkci : k.val < ci.val.length := by omega
    have hkc : k.val < cells.val.length := by omega
    have hkp : k.val < ps.val.length := by omega
    have hindex0 : Slice.index_usize ci k = ok ci.val[k.val]! := by
      simp [Slice.index_usize, hkci]
    have hindex1 : Slice.index_usize indices k = ok indices.val[k.val]! := by
      simp [Slice.index_usize, hlt]
    have hindex2 : Slice.index_usize cells k = ok cells.val[k.val]! := by
      simp [Slice.index_usize, hkc]
    have hindex3 : Slice.index_usize ps k = ok ps.val[k.val]! := by
      simp [Slice.index_usize, hkp]
    obtain ⟨s1, hup1, hs1⟩ := h.update_spec self pre
      (Array.to_slice (core.num.U64.to_be_bytes (UScalar.cast .U64 ci.val[k.val]!))) hself
    obtain ⟨s2, hup2, hs2⟩ := h.update_spec s1 _
      (Array.to_slice (core.num.U64.to_be_bytes indices.val[k.val]!)) hs1
    obtain ⟨s3, hup3, hs3⟩ := h.update_spec s2 _ (Array.to_slice cells.val[k.val]!) hs2
    obtain ⟨s4, hup4, hs4⟩ := h.update_spec s3 _ (Array.to_slice ps.val[k.val]!) hs3
    have hs : ShaRep sha256.portable.Sha256.update sha256.portable.Sha256.finish s4
        (pre ++ challengeRow ci indices cells ps k.val) := by
      simpa only [Array.to_slice, challenge_to_be_bytes, challengeRow, List.append_assoc] using hs4
    have hin : k.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
      have := (Slice.len indices).hBounds
      simp only [Slice.len_val, Slice.length] at this
      omega
    let k' : Usize := UScalar.ofNatCore (k.val + 1) hin
    have hk' : k'.val = k.val + 1 := UScalar.ofNatCore_val_eq _
    have hadd : k + 1#usize = ok k' := challenge_add k 1#usize hin
    obtain ⟨next, hloop, hrep⟩ := ih s4 (pre ++ challengeRow ci indices cells ps k.val)
      hs k' (by omega) (by omega)
    refine ⟨next, ?_, ?_⟩
    · rw [challenge.challenge_in_parts_portable_loop1, loop.eq_1]
      simp only [challenge.challenge_in_parts_portable_loop1.body, htest, if_true,
        hindex0, hindex1, hindex2, hindex3, bind_tc_ok, lift, hup1, hup2,
        hup3, hup4, hadd]
      exact hloop
    · rw [List.drop_eq_getElem_cons (by simp [hlt])]
      simpa only [List.flatMap_cons, List.getElem_range, hk', List.append_assoc] using hrep

theorem challenge_portable_refinement (hsha : ShaCorrect)
    (unique : Slice (Aeneas.Std.Array U8 48#usize))
    (ci : Slice Usize) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (ps : Slice (Aeneas.Std.Array U8 48#usize))
    (hlen : ci.val.length = indices.val.length ∧ cells.val.length = indices.val.length ∧
      ps.val.length = indices.val.length) :
    challenge.challenge_in_parts_portable unique ci indices cells ps =
      ok (frEncode (Fr.hashToBlsField (Model.challengePreimage
        (unique.val.map arrayBytes).toArray (ci.val.map (·.val)).toArray
        (indices.val.map (·.val)).toArray (cells.val.map arrayBytes).toArray
        (ps.val.map arrayBytes).toArray))) := by
  have h := hsha.portable
  obtain ⟨s0, hnew, hs0⟩ := h.new_spec
  obtain ⟨s1, hup1, hs1⟩ := h.update_spec s0 [] (Array.to_slice challenge.DOMAIN) hs0
  obtain ⟨s2, hup2, hs2⟩ := h.update_spec s1 _
    (Array.to_slice (core.num.U64.to_be_bytes (UScalar.cast .U64 FIELD_ELEMENTS_PER_BLOB))) hs1
  obtain ⟨s3, hup3, hs3⟩ := h.update_spec s2 _
    (Array.to_slice (core.num.U64.to_be_bytes (UScalar.cast .U64 FIELD_ELEMENTS_PER_CELL))) hs2
  obtain ⟨s4, hup4, hs4⟩ := h.update_spec s3 _
    (Array.to_slice (core.num.U64.to_be_bytes (UScalar.cast .U64 (Slice.len unique)))) hs3
  obtain ⟨s5, hup5, hs5⟩ := h.update_spec s4 _
    (Array.to_slice (core.num.U64.to_be_bytes (UScalar.cast .U64 (Slice.len indices)))) hs4
  have hs : ShaRep sha256.portable.Sha256.update sha256.portable.Sha256.finish s5
      (challengeHeader (Slice.len unique) (Slice.len indices)) := by
    simpa only [Array.to_slice, List.nil_append, challenge_to_be_bytes, challengeHeader] using hs5
  obtain ⟨s6, hl0, hs6⟩ := challenge_portable_loop0_eq h s5 _ hs unique 0#usize (by simp)
  obtain ⟨s7, hl1, hs7⟩ := challenge_portable_loop1_eq h s6 _ hs6 ci indices cells ps
    0#usize hlen (by simp)
  obtain ⟨digest, hfinish, hdigest⟩ := h.finish_spec s7 _ hs7
  simp only [UScalar.ofNatCore_val_eq, List.drop_zero] at hdigest
  rw [challenge_model_bytes unique ci indices cells ps hlen] at hdigest
  unfold challenge.challenge_in_parts_portable
  simp only [hnew, bind_tc_ok, lift, hup1, hup2, hup3, hup4, hup5, hl0, hl1, hfinish]
  rw [FrScalar.fr_from_bytes_reduced_refines, hdigest]
  rfl


/-- Runtime SHA selection preserves the challenge and consumes no verifier state. -/
theorem verifier_challenge_refinement [RuntimeFeatures]
    (hsha : ShaCorrect)
    (self : verify.CellBatchVerifier) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (ps : Slice (Aeneas.Std.Array U8 48#usize))
    (hlen : self.commitments.index_of_cell.val.length = indices.val.length ∧
      cells.val.length = indices.val.length ∧ ps.val.length = indices.val.length) :
    self.challenge indices cells ps =
      ok (frEncode (Fr.hashToBlsField (Model.challengePreimage
        (self.commitments.unique.val.map arrayBytes).toArray
        (self.commitments.index_of_cell.val.map (·.val)).toArray
        (indices.val.map (·.val)).toArray (cells.val.map arrayBytes).toArray
        (ps.val.map arrayBytes).toArray))) := by
  unfold verify.CellBatchVerifier.challenge
  simp only [sha_available, bind_tc_ok]
  split
  · exact challenge_refinement hsha _ _ _ _ _ hlen
  · exact challenge_portable_refinement hsha _ _ _ _ _ hlen

end LeanBlsSimd.Kzg
