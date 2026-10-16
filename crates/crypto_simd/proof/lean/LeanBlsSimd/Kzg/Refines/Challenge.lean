import LeanBlsSimd.Kzg.Externals
import LeanBlsSimd.Kzg.Model

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg
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

private theorem challenge_extend (v : alloc.vec.Vec U8) (s : Slice U8)
    (hb : v.val.length + s.val.length ≤ Usize.max) :
    ∃ out, alloc.vec.Vec.extend_from_slice core.clone.CloneU8 v s = ok out ∧
      out.val = v.val ++ s.val := by
  have hc : Slice.clone core.clone.CloneU8.clone s = ok s := by
    obtain ⟨s', hc, he⟩ := WP.spec_imp_exists
      (Slice.clone_spec (s := s) (clone := core.clone.CloneU8.clone) (by intros; rfl))
    simpa only [← he] using hc
  change Slice.clone (liftFun1 core.clone.impls.CloneU8.clone) s = ok s at hc
  refine ⟨⟨v.val ++ s.val, by simpa using hb⟩, ?_, rfl⟩
  simp only [alloc.vec.Vec.extend_from_slice, hb, _root_.dite_true]
  split
  · rename_i s' he
    have heq : s' = s := by simpa only [hc, ok.injEq] using he.symm
    subst s'
    rfl
  · rename_i err he
    simp only [hc] at he
    cases he
  · rename_i he
    simp only [hc] at he
    cases he

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

private theorem push_u64_loop_eq (self : challenge.Preimage) (value : U64)
    (shift : I32) (n : Nat) (hn : n ≤ 8) (hs : shift.val = 8 * (n : Int))
    (hb : self.bytes.val.length + n ≤ Usize.max) :
    ∃ next, challenge.Preimage.push_u64_loop self value shift = ok next ∧
      next.bytes.val = self.bytes.val ++ challengeBE value n := by
  induction n generalizing self shift with
  | zero =>
    have hstop : ¬ shift > 0#i32 := by simp [IScalar.lt_equiv, hs]
    refine ⟨self, ?_, by simp [challengeBE]⟩
    rw [challenge.Preimage.push_u64_loop, loop.eq_1]
    simp only [challenge.Preimage.push_u64_loop.body, hstop, if_false]
  | succ n ih =>
    have hpos : shift > 0#i32 := by simp [IScalar.lt_equiv, hs]
    obtain ⟨shift', hsub, hshift'⟩ := WP.spec_imp_exists
      (@I32.sub_spec shift 8#i32 (by scalar_tac) (by scalar_tac))
    have hs' : shift'.val = 8 * (n : Int) := by simp only [IScalar.ofInt_val_eq] at hshift'; omega
    have hshift : value >>> shift' = ok (⟨value.bv.ushiftRight (8*n)⟩ : U64) := by
      show UScalar.shiftRight_IScalar value shift' = _
      have hnonneg : 0 ≤ shift'.val := by omega
      have hsize : 8*n < 64 := by omega
      have hnat : shift'.toNat = 8*n := by change shift'.val.toNat = _; omega
      simp only [UScalar.shiftRight_IScalar, hnonneg, if_true, hnat,
        UScalar.shiftRight, UScalarTy.numBits, hsize]
    have hcast : UScalar.cast .U8 (⟨value.bv.ushiftRight (8*n)⟩ : U64) =
        challengeByte value (8*n) := by
      apply UScalar.eq_of_val_eq
      rw [UScalar.cast_val_eq]
      change (value.bv.ushiftRight (8*n)).toNat % 256 =
        (value.val >>> (8*n)) % 256
      exact congrArg (· % 256) (BitVec.toNat_ushiftRight value.bv (8*n))
    have hpushBound : self.bytes.val.length + 1 ≤ Usize.max := by omega
    let v : alloc.vec.Vec U8 :=
      ⟨self.bytes.val ++ [challengeByte value (8*n)], by simpa using hpushBound⟩
    have hpush : alloc.vec.Vec.push self.bytes (challengeByte value (8*n)) = ok v := by
      simp [alloc.vec.Vec.push, hpushBound, v]
    obtain ⟨next, hloop, hval⟩ := ih ⟨v⟩ shift' (by omega) hs'
      (by simp [v]; omega)
    refine ⟨next, ?_, ?_⟩
    · rw [challenge.Preimage.push_u64_loop, loop.eq_1]
      simp only [challenge.Preimage.push_u64_loop.body, hpos, if_true, hsub, bind_tc_ok,
        hshift, lift, hcast, hpush]
      exact hloop
    · simpa [v, challengeBE_succ, List.append_assoc] using hval

private theorem push_u64_eq (self : challenge.Preimage) (value : U64)
    (hb : self.bytes.val.length + 8 ≤ Usize.max) :
    ∃ next, challenge.Preimage.push_u64 self value = ok next ∧
      next.bytes.val = self.bytes.val ++ challengeBE value := by
  exact push_u64_loop_eq self value 64#i32 8 (by decide) (by decide) hb

private theorem challenge_loop0_eq (self : challenge.Preimage)
    (unique : Slice (Aeneas.Std.Array U8 48#usize)) (i : Usize)
    (hi : i.val ≤ unique.val.length)
    (hb : self.bytes.val.length + (unique.val.length - i.val)*48 ≤ Usize.max) :
    ∃ next, challenge.Preimage.challenge_loop0 self unique i = ok next ∧
      next.bytes.val = self.bytes.val ++ (unique.val.drop i.val).flatMap (·.val) := by
  induction hn : unique.val.length - i.val generalizing self i with
  | zero =>
    have he : i.val = unique.val.length := by omega
    have hstop : ¬ i < Slice.len unique := by simp [he]
    refine ⟨self, ?_, by simp [he]⟩
    rw [challenge.Preimage.challenge_loop0, loop.eq_1]
    simp only [challenge.Preimage.challenge_loop0.body, hstop, if_false]
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
    obtain ⟨v, hext, hv⟩ := challenge_extend self.bytes (Array.to_slice a)
      (by simp [Array.to_slice, a.property]; omega)
    have hv' : v.val = self.bytes.val ++ a.val := hv
    obtain ⟨next, hloop, hval⟩ := ih ⟨v⟩ i' (by omega)
      (by simp [hv', a.property]; omega) (by omega)
    refine ⟨next, ?_, ?_⟩
    · rw [challenge.Preimage.challenge_loop0, loop.eq_1]
      simp only [challenge.Preimage.challenge_loop0.body, htest, if_true, hindex,
        bind_tc_ok, lift, hext, hadd]
      exact hloop
    · rw [List.drop_eq_getElem_cons hlt]
      simpa only [List.flatMap_cons, hi', hv', List.append_assoc] using hval

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

private theorem challenge_loop1_eq (self : challenge.Preimage)
    (ci : Slice Usize) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (ps : Slice (Aeneas.Std.Array U8 48#usize)) (k : Usize)
    (hlen : ci.val.length = indices.val.length ∧ cells.val.length = indices.val.length ∧
      ps.val.length = indices.val.length)
    (hk : k.val ≤ indices.val.length)
    (hb : self.bytes.val.length + (indices.val.length - k.val)*2112 ≤ Usize.max) :
    ∃ next, challenge.Preimage.challenge_loop1 self ci indices cells ps k = ok next ∧
      next.bytes.val = self.bytes.val ++
        ((List.range indices.val.length).drop k.val).flatMap (challengeRow ci indices cells ps) := by
  induction hn : indices.val.length - k.val generalizing self k with
  | zero =>
    have he : k.val = indices.val.length := by omega
    have hstop : ¬ k < Slice.len indices := by simp [he]
    refine ⟨self, ?_, by simp [he]⟩
    rw [challenge.Preimage.challenge_loop1, loop.eq_1]
    simp only [challenge.Preimage.challenge_loop1.body, hstop, if_false]
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
    obtain ⟨s1, hpush0, hs1⟩ := push_u64_eq self (UScalar.cast .U64 ci.val[k.val]!) (by omega)
    obtain ⟨s2, hpush1, hs2⟩ := push_u64_eq s1 indices.val[k.val]!
      (by simp [hs1, challengeBE_length]; omega)
    obtain ⟨v1, hext0, hv1⟩ := challenge_extend s2.bytes (Array.to_slice cells.val[k.val]!)
      (by simp [hs2, hs1, Array.to_slice, challengeBE_length]; omega)
    obtain ⟨v2, hext1, hv2⟩ := challenge_extend v1 (Array.to_slice ps.val[k.val]!)
      (by simp [hv1, hs2, hs1, Array.to_slice, challengeBE_length]; omega)
    have hv : v2.val = self.bytes.val ++ challengeRow ci indices cells ps k.val := by
      simp only [hv2, hv1, hs2, hs1, Array.to_slice, challengeRow, List.append_assoc]
    have hin : k.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
      have := (Slice.len indices).hBounds
      simp only [Slice.len_val, Slice.length] at this
      omega
    let k' : Usize := UScalar.ofNatCore (k.val + 1) hin
    have hk' : k'.val = k.val + 1 := UScalar.ofNatCore_val_eq _
    have hadd : k + 1#usize = ok k' := challenge_add k 1#usize hin
    obtain ⟨next, hloop, hval⟩ := ih ⟨v2⟩ k' (by omega)
      (by simp [hv, challengeRow_length]; omega) (by omega)
    refine ⟨next, ?_, ?_⟩
    · rw [challenge.Preimage.challenge_loop1, loop.eq_1]
      simp only [challenge.Preimage.challenge_loop1.body, htest, if_true,
        hindex0, hindex1, hindex2, hindex3, bind_tc_ok, lift, hpush0, hpush1,
        hext0, hext1, hadd]
      exact hloop
    · rw [List.drop_eq_getElem_cons (by simp [hlt])]
      simpa only [List.flatMap_cons, List.getElem_range, hk', hv, List.append_assoc] using hval

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

theorem challenge_refinement [e : KzgExternals] (h : ExternalsCorrect e)
    (old : challenge.Preimage) (unique : Slice (Aeneas.Std.Array U8 48#usize))
    (ci : Slice Usize) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (ps : Slice (Aeneas.Std.Array U8 48#usize))
    (hlen : ci.val.length = indices.val.length ∧ cells.val.length = indices.val.length ∧
      ps.val.length = indices.val.length ∧ unique.val.length ≤ indices.val.length)
    (hb : cells.val.length * 2048 ≤ Isize.max.toNat) :
    let preimage := Model.challengePreimage (unique.val.map arrayBytes).toArray
      (ci.val.map (·.val)).toArray (indices.val.map (·.val)).toArray
      (cells.val.map arrayBytes).toArray (ps.val.map arrayBytes).toArray
    ∃ next, challenge.Preimage.challenge old unique ci indices cells ps =
      ok (frEncode (Fr.hashToBlsField preimage), next) ∧ bytes next.bytes.val = preimage := by
  dsimp only
  have hcapacity : 48 + unique.val.length*48 + indices.val.length*2112 ≤ Usize.max := by
    rcases System.Platform.numBits_eq with hn | hn <;>
      norm_num [Isize.max, Isize.numBits, Usize.max, Usize.numBits,
        UScalarTy.numBits, IScalarTy.numBits, hn] at hb ⊢ <;> omega
  let empty := alloc.vec.Vec.new U8
  have hclear : alloc.vec.Vec.resize core.clone.CloneU8 old.bytes 0#usize 0#u8 = ok empty := by
    simp [alloc.vec.Vec.resize, List.resize, empty, alloc.vec.Vec.new]
  obtain ⟨v0, hext, hv0⟩ := challenge_extend empty (Array.to_slice challenge.DOMAIN)
    (by simp [empty, Array.to_slice, challenge.DOMAIN.property]; scalar_tac)
  have hv0' : v0.val = challenge.DOMAIN.val := by simpa [empty, alloc.vec.Vec.new] using hv0
  obtain ⟨s1, hp1, hv1⟩ := push_u64_eq ⟨v0⟩ (UScalar.cast .U64 FIELD_ELEMENTS_PER_BLOB)
    (by simp [hv0', challenge.DOMAIN.property]; scalar_tac)
  obtain ⟨s2, hp2, hv2⟩ := push_u64_eq s1 (UScalar.cast .U64 FIELD_ELEMENTS_PER_CELL)
    (by simp [hv1, hv0', challengeBE_length, challenge.DOMAIN.property]; scalar_tac)
  obtain ⟨s3, hp3, hv3⟩ := push_u64_eq s2 (UScalar.cast .U64 (Slice.len unique))
    (by simp [hv2, hv1, hv0', challengeBE_length, challenge.DOMAIN.property]; scalar_tac)
  obtain ⟨s4, hp4, hv4⟩ := push_u64_eq s3 (UScalar.cast .U64 (Slice.len indices))
    (by simp [hv3, hv2, hv1, hv0', challengeBE_length, challenge.DOMAIN.property]; scalar_tac)
  have hheader : s4.bytes.val = challengeHeader (Slice.len unique) (Slice.len indices) := by
    simp only [hv4, hv3, hv2, hv1, hv0', challengeHeader]
  obtain ⟨s5, hl0, hv5⟩ := challenge_loop0_eq s4 unique 0#usize (by simp)
    (by simp [hheader, challengeHeader_length]; omega)
  obtain ⟨next, hl1, hv6⟩ := challenge_loop1_eq s5 ci indices cells ps 0#usize
    ⟨hlen.1, hlen.2.1, hlen.2.2.1⟩ (by simp)
    (by simp [hv5, hheader, challengeHeader_length]; omega)
  have hbytes : bytes next.bytes.val = Model.challengePreimage (unique.val.map arrayBytes).toArray
      (ci.val.map (·.val)).toArray (indices.val.map (·.val)).toArray
      (cells.val.map arrayBytes).toArray (ps.val.map arrayBytes).toArray := by
    simp only [hv6, hv5, hheader, UScalar.ofNatCore_val_eq, List.drop_zero]
    exact challenge_model_bytes unique ci indices cells ps ⟨hlen.1, hlen.2.1, hlen.2.2.1⟩
  refine ⟨next, ?_, hbytes⟩
  have hhash := h.blst.hash (alloc.vec.Vec.deref next.bytes)
  simp only [alloc.vec.Vec.deref, hbytes] at hhash
  unfold challenge.Preimage.challenge
  simp only [hclear, bind_tc_ok, lift, hext, hp1, hp2, hp3, hp4, hl0, hl1,
    blst_ops.hash_to_fr, alloc.vec.Vec.deref, hhash]

end LeanBlsSimd.Kzg
