import LeanBlsSimd.Kzg.Refines.Roots
import LeanBlsSimd.Kzg.Refines.Bits
import LeanBlsSimd.Kzg.Setup
import EthLib.Cryptography.Proofs.Kzg.Polynomials
import EthLib.Cryptography.Proofs.Bls.FrZMod

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls
open core.iter.range core.ops.range

namespace LeanBlsSimd.Kzg

local instance : Inhabited blst.blst_fr := ⟨frEncode 0⟩

set_option maxRecDepth 16000
set_option maxHeartbeats 2000000

private theorem inverse_loop (roots : Slice blst.blst_fr) (target : List blst.blst_fr)
    (hrlen : roots.val.length = 64) (htlen : target.length = 64)
    (hlookup : ∀ j, 0 < j → j < 64 → roots.val[64-j]! = target[j]!)
    (acc : alloc.vec.Vec blst.blst_fr) (i : Usize) (hi : 0 < i.val ∧ i.val ≤ 64)
    (ha : acc.val = target.take i.val) :
    ∃ out, domain.inverse_roots_loop roots 64#usize acc i = ok out ∧ out.val = target := by
  induction hk : 64 - i.val generalizing i acc with
  | zero =>
    have he : i.val = 64 := by omega
    refine ⟨acc, ?_, ?_⟩
    · rw [domain.inverse_roots_loop, loop.eq_1]
      simp [domain.inverse_roots_loop.body, UScalar.lt_equiv, he]
    · simpa [he, ← htlen] using ha
  | succ k ih =>
    have hil : i.val < 64 := by omega
    have hib : 64 < 2^UScalarTy.Usize.numBits := by
      rcases System.Platform.numBits_eq with h | h <;> simp [UScalarTy.numBits, h]
    let j : Usize := UScalar.ofNatCore (64 - i.val) (by omega)
    let i' : Usize := UScalar.ofNatCore (i.val + 1) (by omega)
    have hj : j.val = 64 - i.val := UScalar.ofNatCore_val_eq _
    have hi' : i'.val = i.val + 1 := UScalar.ofNatCore_val_eq _
    have hsub : 64#usize - i = ok j := by
      show UScalar.sub _ _ = _
      simp only [UScalar.sub, UScalar.ofNatCore_val_eq, Nat.not_lt.mpr hi.2, if_false,
        Result.ok.injEq]
      apply (UScalar.eq_equiv_bv_eq _ _).mpr
      exact (UScalar.ofNatCore_bv _ _).symm
    have hadd : i + 1#usize = ok i' := by
      show UScalar.tryMk .Usize (i.val + (1#usize).val) = _
      simp [UScalar.tryMk, UScalar.tryMkOpt, Result.ofOption, i',
        show i.val + 1 < 2^System.Platform.numBits by change i.val + 1 < 2^UScalarTy.Usize.numBits; omega]
    have hindex : Slice.index_usize roots j = ok target[i.val]! := by
      rw [← hlookup _ hi.1 hil]
      simp [Slice.index_usize, hj, hrlen, show 64-i.val < 64 by omega]
    have hsize : acc.val.length + 1 ≤ Usize.max := by
      rw [ha, List.length_take, htlen]
      scalar_tac
    let acc' : alloc.vec.Vec blst.blst_fr :=
      ⟨acc.val ++ [target[i.val]!], by simpa using hsize⟩
    have hpush : alloc.vec.Vec.push acc target[i.val]! = ok acc' := by
      simp [alloc.vec.Vec.push, hsize, acc']
    have ha' : acc'.val = target.take i'.val := by
      simp only [acc', ha, hi']
      rw [List.take_add_one, List.getElem?_eq_getElem (by omega : i.val < target.length)]
      simp only [getElem!_pos target i.val (by omega)]
      rfl
    obtain ⟨out, hout, hval⟩ := ih acc' i' (by omega) ha' (by omega)
    refine ⟨out, ?_, hval⟩
    rw [domain.inverse_roots_loop, loop.eq_1]
    simp only [domain.inverse_roots_loop.body, UScalar.lt_equiv, UScalar.ofNatCore_val_eq,
      hil, if_true, hsub, hindex, hpush, hadd, bind_tc_ok]
    exact hout

private theorem inverse_roots_refinement (roots : Slice blst.blst_fr)
    (values : _root_.Array Fr) (hv : values.size = 64)
    (hr : roots.val = values.toList.map frEncode) :
    ∃ out, domain.inverse_roots roots = ok out ∧
      out.val = (Model.inverseRoots values).toList.map frEncode := by
  let target := (Model.inverseRoots values).toList.map frEncode
  have hlen : roots.val.length = 64 := by simp [hr, hv]
  have htlen : target.length = 64 := by simp [target, Model.inverseRoots, hv]
  have htarget (j : Nat) (hj : j < 64) :
      target[j]! = frEncode (if j = 0 then values[0]! else values[64-j]!) := by
    have htb : j < target.length := by omega
    rw [getElem!_pos target j htb]
    simp only [target, List.getElem_map, _root_.Array.getElem_toList,
      Model.inverseRoots, _root_.Array.getElem_ofFn, hv]
  have hlookup (j : Nat) (hj : j < 64) : roots.val[j]! = frEncode values[j]! := by
    rw [hr, getElem!_pos _ j (by simp [hv]; omega)]
    simp [getElem!_pos values j (by omega)]
  have hzero : roots.val[0]! = target[0]! := by rw [hlookup 0 (by decide), htarget 0 (by decide)]; rfl
  let initial : alloc.vec.Vec blst.blst_fr := ⟨[target[0]!], by simp; scalar_tac⟩
  have hinitial : initial.val = target.take (1#usize).val := by
    simp only [UScalar.ofNatCore_val_eq, initial]
    rw [show (1 : Nat) = 0 + 1 by rfl, List.take_add_one,
      List.getElem?_eq_getElem (by omega : 0 < target.length)]
    simp [getElem!_pos target 0 (by omega)]
  obtain ⟨out, hout, hval⟩ := inverse_loop roots target hlen htlen
    (by
      intro j hj hj64
      rw [hlookup (64-j) (by omega), htarget j hj64, if_neg (by omega)])
    initial 1#usize (by decide) hinitial
  refine ⟨out, ?_, hval⟩
  have hn : Slice.len roots = 64#usize := by apply UScalar.eq_of_val_eq; simpa using hlen
  have hindex : Slice.index_usize roots 0#usize = ok target[0]! := by
    rw [← hzero]
    simp [Slice.index_usize, hlen]
  have hpush : alloc.vec.Vec.push (alloc.vec.Vec.with_capacity blst.blst_fr 64#usize)
      target[0]! = ok initial := by
    simp [alloc.vec.Vec.push, alloc.vec.Vec.with_capacity, initial, U32.max_eq]
  unfold domain.inverse_roots
  dsimp only
  simp only [hn, hindex, hpush, bind_tc_ok]
  exact hout

private def cosetIndex (k : Nat) : Nat := BitReversal.reverseBitsAux (64*k) 0 13

private theorem coset_index_lt (k : Nat) : cosetIndex k < 8192 := by
  simpa [cosetIndex, BitReversal.reverseBits] using
    BitReversal.reverseBits_lt_two_pow (64*k) 13

private theorem bit_reversal_get (a : _root_.Array Fr) (j : Nat) (hj : j < a.size) :
    (BitReversal.bitReversalPermutation a)[j]! = a[BitReversal.reverseBits j a.size]! := by
  rw [getElem!_pos (BitReversal.bitReversalPermutation a) j
    (by simpa [BitReversal.size_bitReversalPermutation] using hj),
    BitReversal.getElem_bitReversalPermutation]

private theorem coset_shift_eq (k : Nat) (hk : k < 128) :
    Model.cosetShift k = (Model.roots 13)[cosetIndex k]! := by
  unfold Model.cosetShift rootsOfUnityBrp
  rw [bit_reversal_get _ _ (by simp; omega)]
  simp only [size_computeRootsOfUnity]
  rfl

open scoped EthLib.Cryptography.Bls.Fr in
private theorem coset_shift_ne_zero (k : Nat) (hk : k < 128) : Model.cosetShift k ≠ 0 := by
  rw [coset_shift_eq k hk]
  simp only [Model.roots, computeRootsOfUnity_def]
  let root : Fr := (Fr.ofNat Constants.PRIMITIVE_ROOT_OF_UNITY) ^
    (Fr.ofNat ((Constants.BLS_MODULUS - 1) / 8192))
  change (computePowers root 8192)[cosetIndex k]! ≠ 0
  rw [getElem!_pos (computePowers root 8192) (cosetIndex k)
    (by simpa using coset_index_lt k), getElem_computePowers, Fr.powNat_eq_pow]
  apply pow_ne_zero
  change Fr.powNat (Fr.ofNat 7) _ ≠ 0
  rw [Fr.powNat_eq_pow]
  exact pow_ne_zero _ (by decide)

private def squareIter (i : Nat) : Range U32 :=
  { start := ⟨BitVec.ofNat 32 i⟩, «end» := 6#u32 }

private theorem square_next (i : Fin 6) :
    IteratorRange.next U32.Insts.CoreIterRangeStep (squareIter i.val) =
      ok (some (squareIter i.val).start, squareIter (i.val + 1)) := by
  fin_cases i <;> rfl

private theorem square_step [e : KzgExternals] (h : ExternalsCorrect e)
    (i : Fin 6) (x : Fr) :
    loop (fun (it, p) => cosets.Cosets.new_loop0_loop0.body it p)
      (squareIter i.val, frEncode x) =
    loop (fun (it, p) => cosets.Cosets.new_loop0_loop0.body it p)
      (squareIter (i.val + 1), frEncode (x * x)) := by
  rw [loop.eq_1]
  simp only [cosets.Cosets.new_loop0_loop0.body, square_next i, bind_tc_ok,
    Function.uncurry_apply_pair, blst_ops.fr_mul, h.blst.fr_mul]

private theorem six_squares [e : KzgExternals] (h : ExternalsCorrect e) (x : Fr) :
    cosets.Cosets.new_loop0_loop0 { start := 0#u32, «end» := cosets.LOG_CELL }
      (frEncode x) = ok (frEncode (Fr.powNat x 64)) := by
  unfold cosets.Cosets.new_loop0_loop0
  rw [cosets.LOG_CELL]
  change loop _ (squareIter 0, frEncode x) = _
  rw [square_step h ⟨0, by decide⟩, square_step h ⟨1, by decide⟩,
    square_step h ⟨2, by decide⟩, square_step h ⟨3, by decide⟩,
    square_step h ⟨4, by decide⟩, square_step h ⟨5, by decide⟩]
  have hn : IteratorRange.next U32.Insts.CoreIterRangeStep (squareIter 6) =
      ok (none, squareIter 6) := by rfl
  rw [loop.eq_1]
  simp only [cosets.Cosets.new_loop0_loop0.body, hn, bind_tc_ok, Function.uncurry_apply_pair]
  simp [Fr.powNat]

private def inverseShifts : List blst.blst_fr :=
  (List.range 128).map (fun k => frEncode (Model.cosetShift k).inverse)

private def shiftPowers : List blst.blst_fr :=
  (List.range 128).map (fun k => frEncode (Fr.powNat (Model.cosetShift k) 64))

private theorem shifts_loop [e : KzgExternals] (h : ExternalsCorrect e)
    (roots : alloc.vec.Vec blst.blst_fr)
    (hr : roots.val = (Model.roots 13).toList.map frEncode)
    (iter : Range Usize) (he : iter.end = 128#usize) (hs : iter.start.val ≤ 128)
    (si sp : alloc.vec.Vec blst.blst_fr)
    (hi : si.val = inverseShifts.take iter.start.val)
    (hp : sp.val = shiftPowers.take iter.start.val) :
    ∃ si' sp', cosets.Cosets.new_loop0 iter roots si sp = ok (si', sp') ∧
      si'.val = inverseShifts ∧ sp'.val = shiftPowers := by
  induction hk : 128 - iter.start.val generalizing iter si sp with
  | zero =>
    have hj : iter.start.val = 128 := by omega
    have hn := Refinement.next_ge iter (by simp [he, hj])
    refine ⟨si, sp, ?_, ?_, ?_⟩
    · rw [cosets.Cosets.new_loop0, loop.eq_1]
      simp only [cosets.Cosets.new_loop0.body, hn, bind_tc_ok, Function.uncurry_apply_pair]
    · simpa [hj, inverseShifts] using hi
    · simpa [hj, shiftPowers] using hp
  | succ d ih =>
    have hj : iter.start.val < 128 := by omega
    obtain ⟨iter', hj', he', hn⟩ := Refinement.next_lt iter (by simp [he, hj])
    have hbound : 8192 < 2^UScalarTy.Usize.numBits := by
      rcases System.Platform.numBits_eq with h | h <;> simp [UScalarTy.numBits, h]
    let offset : Usize := UScalar.ofNatCore (64*iter.start.val) (by omega)
    let index : Usize := ⟨BitVec.ofNat _ (cosetIndex iter.start.val)⟩
    have hoff : offset.val = 64*iter.start.val := UScalar.ofNatCore_val_eq _
    have hidx : index.val = cosetIndex iter.start.val := by
      change (cosetIndex iter.start.val) % 2^UScalarTy.Usize.numBits = _
      exact Nat.mod_eq_of_lt (by have := coset_index_lt iter.start.val; omega)
    have hmul : FIELD_ELEMENTS_PER_CELL * iter.start = ok offset := by
      simp only [FIELD_ELEMENTS_PER_CELL]
      show UScalar.tryMk .Usize (64*iter.start.val) = _
      simp [UScalar.tryMk, UScalar.tryMkOpt, Result.ofOption, offset,
        show 64*iter.start.val < 2^System.Platform.numBits by change 64*iter.start.val < 2^UScalarTy.Usize.numBits; omega]
    have hrev : domain.reverse_bits offset cosets.LOG_EXT_BLOB = ok index := by
      have hrev := reverse_bits_refinement offset cosets.LOG_EXT_BLOB (by
        simp only [cosets.LOG_EXT_BLOB, UScalar.ofNatCore_val_eq]
        rcases System.Platform.numBits_eq with hb | hb <;> simp [Usize.numBits, hb])
      simpa only [cosets.LOG_EXT_BLOB, UScalar.ofNatCore_val_eq, hoff, index, cosetIndex] using hrev
    have hget : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice blst.blst_fr)
        roots index = ok (frEncode (Model.cosetShift iter.start.val)) := by
      have hib : cosetIndex iter.start.val < (Model.roots 13).size := by
        simpa [Model.roots] using coset_index_lt iter.start.val
      rw [coset_shift_eq iter.start.val hj]
      simp [alloc.vec.Vec.index_usize, hr, hidx, hib]
    have hinverse := h.blst.fr_inverse _ (coset_shift_ne_zero iter.start.val hj)
    have hsizeI : si.val.length + 1 ≤ Usize.max := by
      rw [hi]; simp only [inverseShifts, List.length_take, List.length_map, List.length_range]
      scalar_tac
    have hsizeP : sp.val.length + 1 ≤ Usize.max := by
      rw [hp]; simp only [shiftPowers, List.length_take, List.length_map, List.length_range]
      scalar_tac
    let si' : alloc.vec.Vec blst.blst_fr :=
      ⟨si.val ++ [frEncode (Model.cosetShift iter.start.val).inverse], by simpa using hsizeI⟩
    let sp' : alloc.vec.Vec blst.blst_fr :=
      ⟨sp.val ++ [frEncode (Fr.powNat (Model.cosetShift iter.start.val) 64)], by simpa using hsizeP⟩
    have hpushI : alloc.vec.Vec.push si (frEncode (Model.cosetShift iter.start.val).inverse) = ok si' := by
      simp [alloc.vec.Vec.push, si', hsizeI]
    have hpushP : alloc.vec.Vec.push sp (frEncode (Fr.powNat (Model.cosetShift iter.start.val) 64)) = ok sp' := by
      simp [alloc.vec.Vec.push, sp', hsizeP]
    have hi' : si'.val = inverseShifts.take iter'.start.val := by
      simp only [si', hi, hj']
      rw [List.take_add_one, List.getElem?_eq_getElem (by simp [inverseShifts]; omega)]
      simp [inverseShifts]
    have hp' : sp'.val = shiftPowers.take iter'.start.val := by
      simp only [sp', hp, hj']
      rw [List.take_add_one, List.getElem?_eq_getElem (by simp [shiftPowers]; omega)]
      simp [shiftPowers]
    obtain ⟨si'', sp'', hout, hvalI, hvalP⟩ := ih iter' (he'.trans he) (by omega)
      si' sp' hi' hp' (by omega)
    refine ⟨si'', sp'', ?_, hvalI, hvalP⟩
    rw [cosets.Cosets.new_loop0, loop.eq_1]
    simp only [cosets.Cosets.new_loop0.body, hn, bind_tc_ok, Function.uncurry_apply_pair,
      hmul, hrev, hget, blst_ops.fr_inverse, hinverse, hpushI, six_squares h, hpushP]
    exact hout

theorem cells_per_ext_blob_eq : CELLS_PER_EXT_BLOB = ok 128#usize := by
  have hb : 8192 < 2^UScalarTy.Usize.numBits := by
    rcases System.Platform.numBits_eq with h | h <;> simp [UScalarTy.numBits, h]
  have hm : 2#usize * FIELD_ELEMENTS_PER_BLOB = ok 8192#usize := by
    simp only [FIELD_ELEMENTS_PER_BLOB]
    show UScalar.tryMk .Usize 8192 = _
    have hb' : 8192 < 2^System.Platform.numBits := hb
    simp [UScalar.tryMk, UScalar.tryMkOpt, Result.ofOption, hb']
  unfold CELLS_PER_EXT_BLOB
  rw [hm]
  simp only [bind_tc_ok, FIELD_ELEMENTS_PER_CELL]
  obtain ⟨z, hz, hv, _⟩ := UScalar.div_bv_spec 8192#usize (y := 64#usize) (by decide)
  rw [hz]
  congr 1
  apply UScalar.eq_of_val_eq
  simpa using hv

theorem cosets_new_refinement [e : KzgExternals] (h : ExternalsCorrect e) :
    ∃ c, cosets.Cosets.new = ok c ∧ CosetsRep c := by
  obtain ⟨ext, hext, hextval⟩ := roots_refinement h cosets.LOG_EXT_BLOB (Or.inr (by simp [cosets.LOG_EXT_BLOB]))
  simp only [cosets.LOG_EXT_BLOB, UScalar.ofNatCore_val_eq] at hextval
  obtain ⟨si, sp, hshifts, hsi, hsp⟩ := shifts_loop h ext hextval
    { start := 0#usize, «end» := 128#usize } rfl (by decide)
    (alloc.vec.Vec.with_capacity _ 128#usize) (alloc.vec.Vec.with_capacity _ 128#usize)
    (by simp [alloc.vec.Vec.with_capacity]) (by simp [alloc.vec.Vec.with_capacity])
  obtain ⟨rs, hrs, hrsval⟩ := roots_refinement h cosets.LOG_CELL (Or.inl (by simp [cosets.LOG_CELL]))
  simp only [cosets.LOG_CELL, UScalar.ofNatCore_val_eq] at hrsval
  obtain ⟨inv, hinv, hinvval⟩ := inverse_roots_refinement (alloc.vec.Vec.deref rs)
    (Model.roots 6) (by simp [Model.roots]) hrsval
  have h64 := h.blst.fr_u64 64#u64
  have hinv64 := h.blst.fr_inverse (Fr.ofNat 64) (by decide)
  have hcast : UScalar.cast .U64 FIELD_ELEMENTS_PER_CELL = 64#u64 := by
    apply UScalar.eq_of_val_eq
    simp [FIELD_ELEMENTS_PER_CELL]
  refine ⟨⟨inv, frEncode (Fr.ofNat 64).inverse, si, sp⟩, ?_, ?_⟩
  · unfold cosets.Cosets.new
    rw [hext]
    simp only [bind_tc_ok, cells_per_ext_blob_eq]
    rw [hshifts, hrs]
    simp only [bind_tc_ok, Function.uncurry_apply_pair, hinv, lift]
    rw [hcast]
    change (do
      let x ← blst_ops.fr_from_u64 64#u64
      let y ← blst_ops.fr_inverse x
      ok (cosets.Cosets.mk inv y si sp)) = _
    simp only [blst_ops.fr_from_u64, h64, bind_tc_ok, blst_ops.fr_inverse, UScalar.ofNatCore_val_eq, hinv64]
  · exact ⟨hinvval, rfl, hsi, hsp⟩

end LeanBlsSimd.Kzg
