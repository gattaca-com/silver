import LeanBlsSimd.Kzg.Fr.Arithmetic
import LeanBlsSimd.Kzg.Refines.InverseRoots
import LeanBlsSimd.Kzg.Refines.Bits
import LeanBlsSimd.Kzg.CosetsRep
import EthLib.Cryptography.Proofs.Kzg.Polynomials
import EthLib.Cryptography.Proofs.Kzg.Domain
import EthLib.Cryptography.Proofs.Bls.FrZMod

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls
open core.iter.range core.ops.range

namespace LeanBlsSimd.Kzg

attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero

local instance : Inhabited blst.blst_fr := ⟨frEncode 0⟩

set_option maxRecDepth 16000
set_option maxHeartbeats 2000000

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

private theorem square_step
    (i : Fin 6) (x : Fr) :
    loop (fun (it, p) => cosets.Cosets.new_loop0_loop0.body it p)
      (squareIter i.val, frEncode x) =
    loop (fun (it, p) => cosets.Cosets.new_loop0_loop0.body it p)
      (squareIter (i.val + 1), frEncode (x * x)) := by
  rw [loop.eq_1]
  simp only [cosets.Cosets.new_loop0_loop0.body, square_next i, bind_tc_ok,
    Function.uncurry_apply_pair, FrScalar.fr_mul_refines]

private theorem six_squares (x : Fr) :
    cosets.Cosets.new_loop0_loop0 { start := 0#u32, «end» := cosets.LOG_CELL }
      (frEncode x) = ok (frEncode (Fr.powNat x 64)) := by
  unfold cosets.Cosets.new_loop0_loop0
  rw [cosets.LOG_CELL]
  change loop _ (squareIter 0, frEncode x) = _
  rw [square_step ⟨0, by decide⟩, square_step ⟨1, by decide⟩,
    square_step ⟨2, by decide⟩, square_step ⟨3, by decide⟩,
    square_step ⟨4, by decide⟩, square_step ⟨5, by decide⟩]
  have hn : IteratorRange.next U32.Insts.CoreIterRangeStep (squareIter 6) =
      ok (none, squareIter 6) := by rfl
  rw [loop.eq_1]
  simp only [cosets.Cosets.new_loop0_loop0.body, hn, bind_tc_ok, Function.uncurry_apply_pair]
  simp [Fr.powNat]

private def inverseShifts : List blst.blst_fr :=
  (List.range 128).map (fun k => frEncode (Model.cosetShift k).inverse)

private def shiftPowers : List blst.blst_fr :=
  (List.range 128).map (fun k => frEncode (Fr.powNat (Model.cosetShift k) 64))

private theorem inverse_roots_at (i : Nat) (hi : i < 8192) :
    (Model.inverseRoots (Model.roots 13))[i]! = ((Model.roots 13)[i]!).inverse :=
  Refinement.inverse_roots_get_inverse 8192 (by decide)
    (Nat.dvd_of_mod_eq_zero (by decide)) i hi

private theorem encoded_lookup (values : _root_.Array Fr) (out : alloc.vec.Vec blst.blst_fr)
    (hr : out.val = values.toList.map frEncode) (i : Nat) (hi : i < values.size) :
    out.val[i]! = frEncode values[i]! := by
  rw [hr, getElem!_pos _ i (by simpa using hi)]
  simp only [List.getElem_map, _root_.Array.getElem_toList, getElem!_pos values i hi]

private theorem shifts_loop
    (roots inverse : alloc.vec.Vec blst.blst_fr)
    (hr : roots.val = (Model.roots 13).toList.map frEncode)
    (hirlen : inverse.val.length = 8192)
    (hir : ∀ i, i < 8192 → inverse.val[i]! = frEncode ((Model.roots 13)[i]!).inverse)
    (iter : Range Usize) (he : iter.end = 128#usize) (hs : iter.start.val ≤ 128)
    (si sp : alloc.vec.Vec blst.blst_fr)
    (hi : si.val = inverseShifts.take iter.start.val)
    (hp : sp.val = shiftPowers.take iter.start.val) :
    ∃ si' sp', cosets.Cosets.new_loop0 iter roots inverse si sp = ok (si', sp') ∧
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
    have hinverse : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice blst.blst_fr)
        inverse index = ok (frEncode (Model.cosetShift iter.start.val).inverse) := by
      have hib : cosetIndex iter.start.val < inverse.val.length := by
        rw [hirlen]
        exact coset_index_lt _
      rw [coset_shift_eq iter.start.val hj]
      simpa [alloc.vec.Vec.index_usize, hidx, hib] using
        congrArg (fun x : blst.blst_fr => ok x)
          (hir (cosetIndex iter.start.val) (coset_index_lt _))
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
      hmul, hrev, hget, hinverse, hpushI, six_squares, hpushP]
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

theorem cosets_new_refinement :
    ∃ c, cosets.Cosets.new = ok c ∧ CosetsRep c := by
  obtain ⟨ext, hext, hextval⟩ := roots_refinement cosets.LOG_EXT_BLOB (Or.inr (by simp [cosets.LOG_EXT_BLOB]))
  simp only [cosets.LOG_EXT_BLOB, UScalar.ofNatCore_val_eq] at hextval
  obtain ⟨inverseExt, hinverseExt, hinverseExtVal⟩ := Refinement.inverse_roots_refinement 8192#usize (by decide)
    (alloc.vec.Vec.deref ext) (Model.roots 13) (by simp [Model.roots]) hextval
  have hinverseExtLen : inverseExt.val.length = 8192 := by
    rw [hinverseExtVal]
    simp only [List.length_map, _root_.Array.length_toList, Model.inverseRoots,
      _root_.Array.size_ofFn, Model.roots, size_computeRootsOfUnity]
  have hinverseExtLookup (i : Nat) (hi : i < 8192) :
      inverseExt.val[i]! = frEncode ((Model.roots 13)[i]!).inverse := by
    have hi' : i < (Model.inverseRoots (Model.roots 13)).size := by
      simpa only [Model.inverseRoots, _root_.Array.size_ofFn, Model.roots,
        size_computeRootsOfUnity] using hi
    exact (encoded_lookup _ _ hinverseExtVal i hi').trans (congrArg frEncode (inverse_roots_at i hi))
  obtain ⟨si, sp, hshifts, hsi, hsp⟩ := shifts_loop ext inverseExt hextval
    hinverseExtLen hinverseExtLookup
    { start := 0#usize, «end» := 128#usize } rfl (by decide)
    (alloc.vec.Vec.with_capacity _ 128#usize) (alloc.vec.Vec.with_capacity _ 128#usize)
    (by simp [alloc.vec.Vec.with_capacity]) (by simp [alloc.vec.Vec.with_capacity])
  obtain ⟨rs, hrs, hrsval⟩ := roots_refinement cosets.LOG_CELL (Or.inl (by simp [cosets.LOG_CELL]))
  simp only [cosets.LOG_CELL, UScalar.ofNatCore_val_eq] at hrsval
  obtain ⟨inv, hinv, hinvval⟩ := Refinement.inverse_roots_refinement 64#usize (by decide) (alloc.vec.Vec.deref rs)
    (Model.roots 6) (by simp [Model.roots]) hrsval
  refine ⟨⟨inv, frEncode (Fr.ofNat 64).inverse, si, sp⟩, ?_, ?_⟩
  · unfold cosets.Cosets.new
    rw [hext]
    simp only [bind_tc_ok, hinverseExt, cells_per_ext_blob_eq]
    rw [hshifts, hrs]
    simp only [bind_tc_ok, Function.uncurry_apply_pair, hinv, inverse_cell_size_eq]
  · exact ⟨hinvval, rfl, hsi, hsp⟩

end LeanBlsSimd.Kzg
