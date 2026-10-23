import LeanBlsSimd.Kzg.InterpolationKernel.Basic
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8
import LeanBlsSimd.Kzg.Extender.Write

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

open private bytesBEToNatAux_eq_fromBytesBEAux
  from EthLib.Cryptography.Proofs.Kzg.Polynomials

namespace LeanBlsSimd.Kzg.InterpolationKernel

open Extender Extender.Kernel

local instance : Inhabited blst.blst_fr := ⟨frEncode 0⟩

-- ByteArray and Bytes32 infer different getter terms; comparing them can expand the complete serialized array.
private def byteAt (a : ByteArray) (i : Nat) : UInt8 := a[i]!

private def Encoded (values : _root_.Array Fr) (count : Nat)
    (buffer : Array U8 2048#usize) : Prop :=
  ∀ j, j < 8*count → ∀ b, b < 32 →
    byteAt (arrayBytes buffer) (32*j+b) = byteAt (blsFieldToBytes values[j]!) b

private theorem extract_get (a b : ByteArray) (start stop i : Nat)
    (he : a.extract start stop = b) (hi : i < b.size) :
    byteAt a (start+i) = byteAt b i := by
  unfold byteAt
  have hx : i < (a.extract start stop).size := by rw [he]; exact hi
  have ha : start+i < a.size := ByteArray.getElem_extract_aux hx
  rw [getElem!_pos a (start+i) ha, getElem!_pos b i hi,
    ← ByteArray.getElem_extract hx]
  have hh := congrArg (fun x : ByteArray => x[i]!) he
  simpa only [getElem!_pos (a.extract start stop) i hx, getElem!_pos b i hi] using hh

private theorem encoded_step (values : _root_.Array Fr)
    (buffer : Array U8 2048#usize) (i : Nat) (hi : i < 8)
    (he : Encoded values i buffer) (serialized : Slice U8)
    (hlen : serialized.val.length = 2048)
    (hfields : ∀ lane : Fin 8,
      (bytes serialized.val).extract (i*256+32*lane.val) (i*256+32*(lane.val+1)) =
        blsFieldToBytes values[8*i+lane.val]!)
    (hframe : ∀ j : Fin 2048, j.val < i*256 ∨ i*256+256 ≤ j.val →
      serialized.val[j.val]? = buffer.val[j.val]?) :
    Encoded values (i+1) ⟨serialized.val, hlen⟩ := by
  let written : Array U8 2048#usize := ⟨serialized.val, hlen⟩
  intro j hj b hb
  by_cases hjprev : j < 8*i
  · have hat : 32*j+b < 2048 := by omega
    have hf := hframe ⟨32*j+b, hat⟩ (Or.inl (by change 32*j+b < i*256; omega))
    have hg : serialized.val[32*j+b]! = buffer.val[32*j+b]! := by
      simpa only [List.getElem!_eq_getElem?_getD] using
        congrArg (fun x : Option U8 => x.getD default) hf
    have hprev := he j hjprev b hb
    unfold byteAt at hprev ⊢
    rw [arrayBytes_get buffer _ hat] at hprev
    rw [arrayBytes_get written _ hat]
    exact (congrArg (fun x : U8 => UInt8.ofBitVec x.bv) hg).trans hprev
  · have hl : j-8*i < 8 := by omega
    have hfield := hfields ⟨j-8*i, hl⟩
    have hjval : 8*i+(j-8*i) = j := by omega
    simp only [hjval] at hfield
    have hat : i*256+32*(j-8*i)+b = 32*j+b := by omega
    have hh := extract_get (bytes serialized.val) _ _ _ b hfield
      (by rw [field_bytes_size]; exact hb)
    rw [hat] at hh
    simpa only [arrayBytes] using hh

private theorem encode_loop (sums : Array fr8.Fr8 8#usize) (values : _root_.Array Fr)
    (hs : DataRep (Array.to_slice sums) values)
    (buffer : Array U8 2048#usize) (i : Usize) (hi : i.val ≤ 8)
    (he : Encoded values i.val buffer) :
    ∃ out, interpolation_kernel.store_canonical_loop0 sums buffer i = ok out ∧
      Encoded values 8 out := by
  induction hrem : 8-i.val generalizing i buffer with
  | zero =>
    have hi8 : i.val = 8 := by omega
    refine ⟨buffer, ?_, by simpa only [hi8] using he⟩
    rw [interpolation_kernel.store_canonical_loop0, loop.eq_1]
    simp [interpolation_kernel.store_canonical_loop0.body, vectors_per_cell_eq, UScalar.lt_equiv, hi8]
  | succ rem ih =>
    have hit : i.val < 8 := by omega
    have hil : i.val < sums.val.length := by simpa only [sums.property] using hit
    have hp : Represents sums.val[i.val]! (fun lane => values[8*i.val+lane.val]!) := by
      simpa only [Array.to_slice, getElem!_pos sums.val i.val hil] using hs.2 ⟨i.val, hil⟩
    let offset : Usize := UScalar.ofNatCore (i.val*256) (by scalar_tac)
    have hoff : offset.val = i.val*256 := UScalar.ofNatCore_val_eq _
    have hbound : offset.val+256 ≤ (Array.to_slice buffer).val.length := by
      simp only [hoff, Array.to_slice, buffer.property, UScalar.ofNatCore_val_eq]; omega
    obtain ⟨serialized, hserialize, hlen, hfields, hframe⟩ :=
      to_bytes_refinement sums.val[i.val]! hp.1 (Array.to_slice buffer) offset hbound
    have hlen' : serialized.val.length = 2048 := by
      simpa only [Array.to_slice, buffer.property] using hlen
    let written : Array U8 2048#usize := ⟨serialized.val, hlen'⟩
    have hencoded : Encoded values (i.val+1) written := by
      apply encoded_step values buffer i.val hit he serialized hlen'
      · intro lane
        simpa only [hoff, hp.2 lane] using hfields lane
      · intro j hj
        have hj' : j.val < (Array.to_slice buffer).val.length := by
          simpa only [Array.to_slice, buffer.property] using j.isLt
        simpa only [Array.to_slice] using hframe ⟨j.val, hj'⟩
          (by simpa only [hoff] using hj)
    let i' : Usize := UScalar.ofNatCore (i.val+1) (by scalar_tac)
    have hi' : i'.val = i.val+1 := UScalar.ofNatCore_val_eq _
    obtain ⟨out, hout, ho⟩ := ih written i' (by omega)
      (by simpa only [hi'] using hencoded) (by omega)
    have hindex : Array.index_usize sums i = ok sums.val[i.val]! := by
      simp [Array.index_usize, List.getElem?_eq_getElem hil]
    have hmul : i*256#usize = ok offset := scalar_mul_ok i 256#usize (by scalar_tac)
    have hadd : i+1#usize = ok i' := scalar_add_ok i 1#usize (by scalar_tac)
    have hback : Array.from_slice buffer serialized = written := by
      apply Subtype.ext
      simp only [Array.from_slice, hlen', UScalar.ofNatCore_val_eq, ↓reduceDIte, written]
    refine ⟨out, ?_, ho⟩
    rw [interpolation_kernel.store_canonical_loop0, loop.eq_1]
    have hlt : i < 8#usize := by simpa only [UScalar.lt_equiv] using hit
    have hbody : interpolation_kernel.store_canonical_loop0.body sums buffer i =
        ok (cont (written, i')) := by
      simp only [interpolation_kernel.store_canonical_loop0.body, vectors_per_cell_eq, hlt, if_true,
        hindex, Array.to_slice_mut, lift, Function.uncurry_apply_pair, bytes_per_vector_eq, hmul,
        hserialize, hadd, hback, bind_tc_ok]
    simpa only [hbody] using hout

private def fieldChunk (buffer : Array U8 2048#usize) (i : Nat) (hi : i < 64) :
    Array U8 32#usize :=
  ⟨buffer.val.slice (32*i) (32*(i+1)), by simp [List.slice, buffer.property]; omega⟩

private theorem byteArray_ext_get (a b : ByteArray) (hs : a.size = b.size)
    (hg : ∀ i, i < a.size → byteAt a i = byteAt b i) : a = b := by
  apply ByteArray.ext
  apply _root_.Array.ext hs
  intro i hi hj
  simpa only [getElem!_pos a i hi, getElem!_pos b i hj,
    ByteArray.getElem_eq_getElem_data, byteAt] using hg i hi

private theorem fieldChunk_get (buffer : Array U8 2048#usize)
    (i b : Nat) (hi : i < 64) (hb : b < 32) :
    byteAt (arrayBytes (fieldChunk buffer i hi)) b = byteAt (arrayBytes buffer) (32*i+b) := by
  unfold byteAt
  have hat : 32*i+b < 2048 := by omega
  rw [arrayBytes_get (fieldChunk buffer i hi) b hb, arrayBytes_get buffer _ hat]
  congr 2
  rw [getElem!_pos (fieldChunk buffer i hi).val b
    (by rw [(fieldChunk buffer i hi).property]; exact hb)]
  simp only [fieldChunk, List.slice, List.getElem_take, List.getElem_drop]
  exact (getElem!_pos buffer.val (32*i+b) (by rw [buffer.property]; exact hat)).symm

private theorem fieldChunk_bytes (buffer : Array U8 2048#usize)
    (values : _root_.Array Fr) (he : Encoded values 8 buffer)
    (i : Nat) (hi : i < 64) :
    arrayBytes (fieldChunk buffer i hi) = blsFieldToBytes values[i]! := by
  apply byteArray_ext_get
  · rw [arrayBytes_size, field_bytes_size]
    rfl
  · intro b hb
    have hb' : b < 32 := by simpa only [arrayBytes_size] using hb
    rw [fieldChunk_get buffer i b hi hb']
    exact he i (by omega) b hb'

private theorem decode_field_bytes (value : Fr) :
    bytesToBlsField (blsFieldToBytes value) = .ok value := by
  have hb : value.val < 256^32 := lt_trans value.isLt (by decide)
  have hv : bytesBEToNat (blsFieldToBytes value) = value.val :=
    bytesBEToNat_intToBytesBE_of_lt hb
  have hv' : Fr.bytesBEToNat (blsFieldToBytes value) = value.val := by
    simpa only [bytesBEToNat, Fr.bytesBEToNat, bytesBEToNatAux_eq_fromBytesBEAux] using hv
  simp only [bytesToBlsField, field_bytes_size, Constants.BYTES_PER_FIELD_ELEMENT,
    ne_eq, not_true_eq_false, ↓reduceIte, Fr.fromBytesBE, hv', value.isLt, ↓reduceDIte]

private theorem decode_loop [e : KzgExternals] (h : BlstCorrect e)
    (buffer : Array U8 2048#usize) (values : _root_.Array Fr)
    (hvalues : values.size = 64) (he : Encoded values 8 buffer)
    (out : Slice blst.blst_fr) (hlen : out.val.length = 64)
    (i : Usize) (hi : i.val ≤ 64)
    (hp : ∀ j, j < i.val → out.val[j]! = frEncode values[j]!) :
    ∃ out', interpolation_kernel.store_canonical_loop1 out buffer i = ok out' ∧
      out'.val = values.toList.map frEncode := by
  induction hrem : 64-i.val generalizing i out with
  | zero =>
    have hi64 : i.val = 64 := by omega
    refine ⟨out, ?_, ?_⟩
    · rw [interpolation_kernel.store_canonical_loop1, loop.eq_1]
      simp [interpolation_kernel.store_canonical_loop1.body, FIELD_ELEMENTS_PER_CELL,
        UScalar.lt_equiv, hi64]
    · apply List.ext_getElem
      · simp [hlen, hvalues]
      · intro j hj ht
        have hj64 : j < 64 := by omega
        have hv : j < values.size := by omega
        simpa only [getElem!_pos out.val j hj, getElem!_pos values j hv,
          List.getElem_map, _root_.Array.getElem_toList] using hp j (by omega)
  | succ rem ih =>
    have hit : i.val < 64 := by omega
    let start : Usize := UScalar.ofNatCore (32*i.val) (by scalar_tac)
    let stop : Usize := UScalar.ofNatCore (32*(i.val+1)) (by scalar_tac)
    let i' : Usize := UScalar.ofNatCore (i.val+1) (by scalar_tac)
    have hi' : i'.val = i.val+1 := UScalar.ofNatCore_val_eq _
    let chunk := fieldChunk buffer i.val hit
    let src := Array.to_slice chunk
    have hindex : core.array.Array.index
        (core.ops.index.IndexSlice (core.slice.index.SliceIndexRangeUsizeSlice U8)) buffer
        { start, «end» := stop } = ok src := by
      have hstopn : 32*(i.val+1) ≤ 2048 := by omega
      simp [core.array.Array.index, core.ops.index.IndexSlice, core.slice.index.Slice.index,
        core.slice.index.SliceIndexRangeUsizeSlice.index, start, stop, src, chunk,
        fieldChunk, Array.to_slice, hstopn]
    have hcopy : core.slice.Slice.copy_from_slice core.marker.CopyU8
        (Array.to_slice (Array.repeat 32#usize 0#u8)) src = ok src := by
      simp [core.slice.Slice.copy_from_slice, UScalar.eq_equiv, src, Array.to_slice, chunk.property]
    have hback : Array.from_slice (Array.repeat 32#usize 0#u8) src = chunk := by
      apply Subtype.ext
      simp [src, Array.to_slice, chunk.property]
    have hdecode : blst_ops.fr_from_bytes chunk = ok (some (frEncode values[i.val]!)) := by
      rw [blst_ops.fr_from_bytes, h.fr_bytes, fieldChunk_bytes buffer values he i.val hit,
        decode_field_bytes]
      rfl
    let next := out.set i (frEncode values[i.val]!)
    have hnextlen : next.val.length = 64 := by simp [next, Slice.set, Slice.setAtNat, hlen]
    have hnext : ∀ j, j < i'.val → next.val[j]! = frEncode values[j]! := by
      intro j hj
      by_cases heq : j = i.val
      · subst j
        change (out.val.set i.val (frEncode values[i.val]!))[i.val]! = _
        exact List.getElem!_set _ _ _ (by omega)
      · change (out.val.set i.val (frEncode values[i.val]!))[j]! = _
        rw [List.getElem!_set_ne _ _ _ _ (by omega)]
        exact hp j (by omega)
    obtain ⟨out', hout, ho⟩ := ih next hnextlen i' (by omega) hnext (by omega)
    have hadd : i+1#usize = ok i' := scalar_add_ok i 1#usize (by scalar_tac)
    have hstart : i*BYTES_PER_FIELD_ELEMENT = ok start := by
      simpa only [BYTES_PER_FIELD_ELEMENT, start, UScalar.ofNatCore_val_eq, Nat.mul_comm] using scalar_mul_ok i 32#usize (by scalar_tac)
    have hstop : i'*BYTES_PER_FIELD_ELEMENT = ok stop := by
      simpa only [BYTES_PER_FIELD_ELEMENT, stop, hi', UScalar.ofNatCore_val_eq, Nat.mul_comm] using scalar_mul_ok i' 32#usize (by scalar_tac)
    have hupdate : Slice.update out i (frEncode values[i.val]!) = ok next := by
      simp [Slice.update, List.getElem?_eq_getElem (show i.val < out.val.length by omega)]
      rfl
    refine ⟨out', ?_, ho⟩
    rw [interpolation_kernel.store_canonical_loop1, loop.eq_1]
    have hlt : i < FIELD_ELEMENTS_PER_CELL := by simpa only [FIELD_ELEMENTS_PER_CELL, UScalar.lt_equiv] using hit
    simpa only [interpolation_kernel.store_canonical_loop1.body, hlt, if_true,
      Array.to_slice_mut, lift, Function.uncurry_apply_pair, hstart, hadd, hstop,
      hindex, hcopy, hback, hdecode, hupdate, bind_tc_ok] using hout

theorem store_canonical_refinement [e : KzgExternals] (h : BlstCorrect e)
    (sums : Array fr8.Fr8 8#usize) (values : _root_.Array Fr)
    (hs : DataRep (Array.to_slice sums) values)
    (out : Slice blst.blst_fr) (hlen : out.val.length = 64) :
    ∃ out', interpolation_kernel.store_canonical sums out = ok out' ∧
      out'.val = values.toList.map frEncode := by
  have hsize : values.size = 64 := by
    have hh := hs.1
    simpa only [Array.to_slice, sums.property] using hh
  obtain ⟨buffer, hb, he⟩ := encode_loop sums values hs
    (Array.repeat 2048#usize 0#u8) 0#usize (by decide) (by intro j hj; simp only [UScalar.ofNatCore_val_eq] at hj; omega)
  obtain ⟨out', hout, ho⟩ := decode_loop h buffer values hsize he out hlen 0#usize
    (by decide) (by intro j hj; simp only [UScalar.ofNatCore_val_eq] at hj; omega)
  exact ⟨out', by simp only [interpolation_kernel.store_canonical, hb, hout, bind_tc_ok], ho⟩

end LeanBlsSimd.Kzg.InterpolationKernel
