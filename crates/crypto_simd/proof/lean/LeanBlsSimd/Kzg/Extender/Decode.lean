import LeanBlsSimd.Kzg.Fr.ByteEncode
import LeanBlsSimd.Kzg.Extender.Basic
import LeanBlsSimd.Kzg.Refines.Bits
import EthLib.Cryptography.Proofs.Kzg.BitReversal
import EthLib.Cryptography.Proofs.Kzg.Polynomials

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg Kzg.BitReversal
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender

local instance decodeRawFrInhabited : Inhabited blst.blst_fr := ⟨frEncode 0⟩

theorem scalar_add_ok {ty : UScalarTy} (a b : UScalar ty)
    (h : a.val + b.val < 2 ^ ty.numBits) :
    a + b = ok (UScalar.ofNatCore (a.val + b.val) h) := by
  change UScalar.tryMk ty (a.val + b.val) = _
  simp [UScalar.tryMk, UScalar.tryMkOpt, h, Result.ofOption]

theorem scalar_mul_ok {ty : UScalarTy} (a b : UScalar ty)
    (h : a.val * b.val < 2 ^ ty.numBits) :
    a * b = ok (UScalar.ofNatCore (a.val * b.val) h) := by
  change UScalar.tryMk ty (a.val * b.val) = _
  simp [UScalar.tryMk, UScalar.tryMkOpt, h, Result.ofOption]

def rev (j : Nat) : Nat := reverseBits j 4096

theorem rev_lt (j : Nat) : rev j < 4096 := reverseBits_lt_two_pow j 12

theorem rev_rev (j : Nat) (hj : j < 4096) : rev (rev j) = j :=
  reverseBits_reverseBits (k := 12) hj

theorem rev_injective {i j : Nat} (hi : i < 4096) (hj : j < 4096)
    (h : rev i = rev j) : i = j := by
  simpa [rev_rev i hi, rev_rev j hj] using congrArg rev h

theorem reverse_bits_blob (j : Usize) :
    domain.reverse_bits j cell_extender.LOG_BLOB =
      ok (UScalar.ofNatCore (rev j.val) (by have := rev_lt j.val; scalar_tac)) := by
  rw [reverse_bits_refinement j cell_extender.LOG_BLOB (by
    simp [cell_extender.LOG_BLOB, Usize.numBits]
    rcases System.Platform.numBits_eq with h | h <;> omega)]
  congr 1
  apply UScalar.eq_of_val_eq
  have hb : rev j.val < 2 ^ UScalarTy.Usize.numBits := by
    have := rev_lt j.val
    scalar_tac
  simp only [cell_extender.LOG_BLOB, UScalar.ofNatCore_val_eq]
  change (rev j.val) % 2 ^ UScalarTy.Usize.numBits = rev j.val
  exact Nat.mod_eq_of_lt hb

def blobChunk (blob : Blob) (j : Nat) (hj : j < 4096) :
    Aeneas.Std.Array U8 32#usize :=
  ⟨blob.val.slice (32*j) (32*(j+1)), by
    simp [List.slice, blob.property]
    omega⟩

theorem blobChunk_bytes (blob : Blob) (j : Nat) (hj : j < 4096) :
    arrayBytes (blobChunk blob j hj) = (arrayBytes blob).extract (32*j) (32*(j+1)) := by
  apply ByteArray.ext
  rw [ByteArray.data_extract]
  apply _root_.Array.toList_inj.mp
  simp only [arrayBytes, bytes, blobChunk, List.toList_toArray, _root_.Array.toList_extract]
  simp [List.extract_eq_take_drop, List.slice, List.map_take, List.map_drop]

def chunkVerdict (blob : Blob) (j : Nat) : Option Fr :=
  (bytesToBlsField ((arrayBytes blob).extract (j * 32) ((j+1)*32))).toOption

def storeEvaluation (v : cell_extender.CellExtender) (j : Nat) (f : Fr) :
    cell_extender.CellExtender :=
  { v with evaluations := ⟨v.evaluations.val.set (rev j) (frEncode f), by
      simpa using v.evaluations.property⟩ }

theorem storeEvaluation_invariant (v : cell_extender.CellExtender)
    (hv : StateInvariant v) (j : Nat) (f : Fr) :
    StateInvariant (storeEvaluation v j f) := by
  simpa [StateInvariant, storeEvaluation] using hv

theorem decode_blob_body
    (blob : Blob) (self : cell_extender.CellExtender) (hv : StateInvariant self)
    (j j' : Usize) (hj : j.val < 4096) (hj' : j'.val = j.val + 1) :
    cell_extender.CellExtender.decode_blob_loop.body blob self j =
      (match chunkVerdict blob j.val with
      | none => ok (done (self, j))
      | some value => ok (cont (storeEvaluation self j.val value, j'))) := by
  have hadd : j + 1#usize = ok j' := by
    rw [scalar_add_ok j 1#usize (by scalar_tac)]
    congr 1
    apply UScalar.eq_of_val_eq
    simpa using hj'.symm
  let start : Usize := UScalar.ofNatCore (j.val * 32) (by scalar_tac)
  let stop : Usize := UScalar.ofNatCore (j'.val * 32) (by scalar_tac)
  have hstart : j * BYTES_PER_FIELD_ELEMENT = ok start := by
    simpa [BYTES_PER_FIELD_ELEMENT, start] using scalar_mul_ok j 32#usize (by scalar_tac)
  have hstop : j' * BYTES_PER_FIELD_ELEMENT = ok stop := by
    simpa [BYTES_PER_FIELD_ELEMENT, stop] using scalar_mul_ok j' 32#usize (by scalar_tac)
  let chunk := blobChunk blob j.val hj
  let src : Slice U8 := Array.to_slice chunk
  have hindex : core.array.Array.index
      (core.ops.index.IndexSlice (core.slice.index.SliceIndexRangeUsizeSlice U8)) blob
      { start, «end» := stop } = ok src := by
    have hstopn : 32 * (j.val + 1) ≤ 131072 := by omega
    simp [core.array.Array.index, core.ops.index.IndexSlice, core.slice.index.Slice.index,
      core.slice.index.SliceIndexRangeUsizeSlice.index, start, stop,
      hj', src, chunk, blobChunk, Array.to_slice, Nat.mul_comm, hstopn]
  have hcopy : core.slice.Slice.copy_from_slice core.marker.CopyU8
      (Array.to_slice (Array.repeat 32#usize 0#u8)) src = ok src := by
    simp [core.slice.Slice.copy_from_slice, UScalar.eq_equiv, src,
      Array.to_slice, chunk.property]
  have hback : Array.from_slice (Array.repeat 32#usize 0#u8) src = chunk := by
    apply Subtype.ext
    simp [src, Array.to_slice, chunk.property]
  have hdecode := FrScalar.fr_from_bytes_refines chunk
  dsimp only [chunk] at hdecode
  rw [blobChunk_bytes] at hdecode
  unfold cell_extender.CellExtender.decode_blob_loop.body
  simp only [FIELD_ELEMENTS_PER_BLOB, UScalar.lt_equiv, UScalar.ofNatCore_val_eq,
    hj, if_true, lift, bind_tc_ok, Array.to_slice_mut, Function.uncurry_apply_pair,
    hstart, hadd, hstop, hindex, hcopy, hback]
  rw [hdecode]
  have hlen := hv.2.2.2.2.1
  cases hd : bytesToBlsField ((arrayBytes blob).extract (32*j.val) (32*(j.val+1))) with
  | error err => simp [chunkVerdict, Nat.mul_comm, hd, Except.toOption]
  | ok value =>
    simp only [Except.toOption, Option.map_some, reverse_bits_blob, bind_tc_ok]
    simp [alloc.vec.Vec.index_mut, Slice.index_mut_usize, Slice.index_usize,
      hlen, rev_lt, storeEvaluation, chunkVerdict,
      Nat.mul_comm, hd, Except.toOption, bind_tc_ok]
    rfl

theorem storeEvaluation_previous (v : cell_extender.CellExtender)
    (i j : Nat) (hi : i < 4096) (hj : j < i) (f : Fr) :
    (storeEvaluation v i f).evaluations.val[rev j]! = v.evaluations.val[rev j]! := by
  have hne : rev i ≠ rev j := by
    intro h
    have := rev_injective hi (by omega) h
    omega
  simp [storeEvaluation, hne]

theorem storeEvaluation_current (v : cell_extender.CellExtender)
    (hv : StateInvariant v) (i : Nat) (f : Fr) :
    (storeEvaluation v i f).evaluations.val[rev i]! = frEncode f := by
  have hlen := hv.2.2.2.2.1
  simp [storeEvaluation, hlen, rev_lt]

theorem decode_blob_loop_eq
    (self : cell_extender.CellExtender) (hv : StateInvariant self) (blob : Blob)
    (i : Usize) (hi : i.val ≤ 4096) :
    ∃ next stop, cell_extender.CellExtender.decode_blob_loop self blob i = ok (next, stop) ∧
      StateInvariant next ∧
      next = { self with evaluations := next.evaluations } ∧
      (∀ j, j < i.val → next.evaluations.val[rev j]! = self.evaluations.val[rev j]!) ∧
      (match blobToPolynomialAux (arrayBytes blob) i.val (4096-i.val) with
      | .error _ => stop.val < 4096
      | .ok xs => stop.val = 4096 ∧ ∀ j, j < xs.length →
          next.evaluations.val[rev (i.val+j)]! = frEncode xs[j]!) := by
  induction hk : 4096-i.val generalizing self i with
  | zero =>
    have he : i.val = 4096 := by omega
    refine ⟨self, i, ?_, hv, rfl, fun _ _ => rfl, ?_⟩
    · rw [cell_extender.CellExtender.decode_blob_loop, loop.eq_1]
      simp [cell_extender.CellExtender.decode_blob_loop.body, FIELD_ELEMENTS_PER_BLOB, he]
    · simp [he, blobToPolynomialAux]
  | succ k ih =>
    have hlt : i.val < 4096 := by omega
    let i' : Usize := UScalar.ofNatCore (i.val+1) (by scalar_tac)
    have hi' : i'.val = i.val+1 := UScalar.ofNatCore_val_eq _
    have hbody := decode_blob_body blob self hv i i' hlt hi'
    have haux : blobToPolynomialAux (arrayBytes blob) i.val (k+1) =
        match bytesToBlsField ((arrayBytes blob).extract (i.val*32) ((i.val+1)*32)) with
        | .error _ => .error (.invalidFieldElement (some i.val))
        | .ok f => (blobToPolynomialAux (arrayBytes blob) i'.val k).map (f :: ·) := by
      rw [blobToPolynomialAux]
      simp only [Constants.BYTES_PER_FIELD_ELEMENT, hi']
      cases bytesToBlsField ((arrayBytes blob).extract (i.val*32) ((i.val+1)*32)) <;> rfl
    cases hd : bytesToBlsField ((arrayBytes blob).extract (i.val*32) ((i.val+1)*32)) with
    | error err =>
      refine ⟨self, i, ?_, hv, rfl, fun _ _ => rfl, ?_⟩
      · rw [cell_extender.CellExtender.decode_blob_loop, loop.eq_1]
        simp [hbody, chunkVerdict, hd, Except.toOption]
      · simpa [haux, hd] using hlt
    | ok f =>
      let self' := storeEvaluation self i.val f
      obtain ⟨next, stop, hloop, hn, hf, hp, hr⟩ :=
        ih self' (storeEvaluation_invariant self hv i.val f) i' (by omega) (by omega)
      refine ⟨next, stop, ?_, hn, ?_, ?_, ?_⟩
      · rw [cell_extender.CellExtender.decode_blob_loop, loop.eq_1]
        simpa [hbody, chunkVerdict, hd, Except.toOption, self'] using hloop
      · simpa [self', storeEvaluation] using hf
      · intro j hj
        rw [hp j (by omega)]
        exact storeEvaluation_previous self i.val j hlt hj f
      · rw [haux, hd]
        cases ht : blobToPolynomialAux (arrayBytes blob) i'.val k with
        | error err => simpa [ht, Except.map] using hr
        | ok xs =>
          simp only [ht] at hr
          simp only [Except.map]
          refine ⟨hr.1, ?_⟩
          intro j hj
          cases j with
          | zero =>
            simpa only [Nat.add_zero, List.getElem!_cons_zero] using
              (hp i.val (by omega)).trans (storeEvaluation_current self hv i.val f)
          | succ j =>
            simpa [hi', Nat.add_assoc, Nat.add_left_comm, Nat.add_comm] using
              hr.2 j (by simpa using hj)

theorem decode_blob_refinement
    (self : cell_extender.CellExtender) (hv : StateInvariant self) (blob : Blob) :
    ∃ verdict next, cell_extender.CellExtender.decode_blob self blob = ok (verdict, next) ∧
      StateInvariant next ∧
      next = { self with evaluations := next.evaluations } ∧
      (match blobToPolynomial (arrayBytes blob) with
      | .error _ => verdict = false
      | .ok values => verdict = true ∧ values.size = 4096 ∧
          next.evaluations.val = (bitReversalPermutation values).toList.map frEncode) := by
  obtain ⟨next, stop, hloop, hn, hf, _, hr⟩ :=
    decode_blob_loop_eq self hv blob 0#usize (by decide)
  refine ⟨decide (stop = FIELD_ELEMENTS_PER_BLOB), next, ?_, hn, hf, ?_⟩
  · simp only [cell_extender.CellExtender.decode_blob, hloop, bind_tc_ok,
      Function.uncurry_apply_pair]
  · have hsize : (arrayBytes blob).size = 131072 := by
      simp [arrayBytes, bytes, ByteArray.size, blob.property]
    simp only [UScalar.ofNatCore_val_eq, Nat.sub_zero, Nat.zero_add] at hr
    cases ha : blobToPolynomialAux (arrayBytes blob) 0 4096 with
    | error err =>
      simp only [ha] at hr
      have hne : stop ≠ FIELD_ELEMENTS_PER_BLOB := by
        intro he
        have := congrArg UScalar.val he
        simp only [FIELD_ELEMENTS_PER_BLOB, UScalar.ofNatCore_val_eq] at this
        omega
      simp [blobToPolynomial, hsize, Constants.BYTES_PER_BLOB,
        Constants.BYTES_PER_FIELD_ELEMENT, Constants.FIELD_ELEMENTS_PER_BLOB, ha, hne]
    | ok xs =>
      simp only [ha] at hr
      have hlen := length_blobToPolynomialAux (arrayBytes blob) 0 4096 xs ha
      have hstop : stop = FIELD_ELEMENTS_PER_BLOB := by
        apply UScalar.eq_of_val_eq
        simpa only [FIELD_ELEMENTS_PER_BLOB, UScalar.ofNatCore_val_eq] using hr.1
      simp only [blobToPolynomial, hsize, Constants.BYTES_PER_BLOB,
        ne_eq, not_true_eq_false, if_false, Constants.BYTES_PER_FIELD_ELEMENT,
        Constants.FIELD_ELEMENTS_PER_BLOB, ha]
      change decide (stop = FIELD_ELEMENTS_PER_BLOB) = true ∧ xs.toArray.size = 4096 ∧ _
      refine ⟨by simp [hstop], by simpa using hlen, ?_⟩
      apply List.ext_getElem (by simpa [size_bitReversalPermutation, hlen] using hn.2.2.2.2.1)
      intro j hj hj'
      have hjn : j < 4096 := by simpa [hn.2.2.2.2.1] using hj
      have hget := hr.2 (rev j) (by simpa [hlen] using rev_lt j)
      rw [rev_rev j hjn] at hget
      rw [getElem!_pos next.evaluations.val j hj] at hget
      rw [List.getElem_map, _root_.Array.getElem_toList, getElem_bitReversalPermutation]
      change next.evaluations.val[j] = frEncode xs.toArray[reverseBits j xs.toArray.size]!
      simpa only [List.size_toArray, hlen, rev, List.getElem!_toArray] using hget

end LeanBlsSimd.Kzg.Extender
