import LeanBlsSimd.Kzg.Extender.Kernel.Fr8
import LeanBlsSimd.Kzg.Extender.Decode

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel

def shiftedValues (values : _root_.Array Fr) : _root_.Array Fr :=
  _root_.Array.ofFn (n := 4096) fun i => values[i.val]! * shiftFactor i.val

private def ShiftPrefix (data : alloc.vec.Vec fr8.Fr8) (values : _root_.Array Fr)
    (count : Nat) : Prop :=
  data.val.length = 512 ∧ ∀ v : Fin 512,
    Represents data.val[v.val]! (fun lane =>
      if v.val < count then values[8 * v.val + lane.val]! * shiftFactor (8 * v.val + lane.val)
      else values[8 * v.val + lane.val]!)

private theorem shift_loop (kernel : extension_kernel.ExtensionKernel)
    (hk : StateInvariant kernel) (values : _root_.Array Fr)
    (data : alloc.vec.Vec fr8.Fr8) (i : Usize) (hi : i.val ≤ 512)
    (hd : ShiftPrefix data values i.val) :
    ∃ out, extension_kernel.ExtensionKernel.extend_loop0 kernel.shift data i = ok out ∧
      ShiftPrefix out values 512 := by
  induction hrem : 512 - i.val generalizing i data with
  | zero =>
    have he : i.val = 512 := by omega
    refine ⟨data, ?_, by simpa only [he] using hd⟩
    rw [extension_kernel.ExtensionKernel.extend_loop0, loop.eq_1]
    simp [extension_kernel.ExtensionKernel.extend_loop0.body, alloc.vec.Vec.len,
      UScalar.lt_equiv, hd.1, he]
  | succ rem ih =>
    have hit : i.val < 512 := by omega
    have hil : i.val < data.val.length := by rw [hd.1]; exact hit
    have his : i.val < kernel.shift.val.length := by rw [hk.2.2.1]; exact hit
    have hrep : Represents data.val[i.val]!
        (fun lane => values[8 * i.val + lane.val]!) := by
      simpa only [lt_self_iff_false, if_false] using hd.2 ⟨i.val, hit⟩
    obtain ⟨product, hmul, hp⟩ := mul_multiplier_refinement
      data.val[i.val]! kernel.shift.val[i.val]!
      (fun lane => values[8 * i.val + lane.val]!)
      (fun lane => shiftFactor (8 * i.val + lane.val)) hrep (hk.2.2.2.2 ⟨i.val, hit⟩)
    let next := alloc.vec.Vec.set data i product
    have hprefix : ShiftPrefix next values (i.val + 1) := by
      refine ⟨by simpa [next, alloc.vec.Vec.set] using hd.1, ?_⟩
      intro v
      by_cases he : v.val = i.val
      · have hve : v = ⟨i.val, hit⟩ := Fin.ext he
        subst v
        simpa [next, alloc.vec.Vec.set, List.getElem!_set, hil] using hp
      · have hlt : (v.val < i.val + 1) = (v.val < i.val) := propext (by omega)
        simpa only [next, alloc.vec.Vec.set,
          List.getElem!_set_ne data.val i.val v.val product (by omega), hlt]
          using hd.2 v
    let i' : Usize := UScalar.ofNatCore (i.val + 1) (by scalar_tac)
    have hi' : i'.val = i.val + 1 := UScalar.ofNatCore_val_eq _
    have hadd : i + 1#usize = ok i' := scalar_add_ok i 1#usize (by scalar_tac)
    have hindex : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice fr8.Fr8)
        data i = ok data.val[i.val]! := by
      simp [alloc.vec.Vec.index_usize, List.getElem?_eq_getElem hil]
    have hshift : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice fr8.Fr8)
        kernel.shift i = ok kernel.shift.val[i.val]! := by
      simp [alloc.vec.Vec.index_usize, List.getElem?_eq_getElem his]
    have hmut : alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice fr8.Fr8)
        data i = ok (data.val[i.val]!, alloc.vec.Vec.set data i) := by
      have hindex' : alloc.vec.Vec.index_usize data i = ok data.val[i.val]! := by
        simpa only [alloc.vec.Vec.index_slice_index] using hindex
      simp only [alloc.vec.Vec.index_mut_slice_index, alloc.vec.Vec.index_mut_usize, hindex']
    obtain ⟨out, hout, ho⟩ := ih next i' (by omega) (by simpa only [hi'] using hprefix) (by omega)
    refine ⟨out, ?_, ho⟩
    rw [extension_kernel.ExtensionKernel.extend_loop0, loop.eq_1]
    have hlt : i < alloc.vec.Vec.len data := by
      simpa only [UScalar.lt_equiv, alloc.vec.Vec.len, UScalar.ofNatCore_val_eq] using hil
    simpa only [extension_kernel.ExtensionKernel.extend_loop0.body, hlt, if_true,
      hindex, hshift, hmul, hmut, hadd, bind_tc_ok, next] using hout

theorem shift_refinement (kernel : extension_kernel.ExtensionKernel)
    (hk : StateInvariant kernel) (data : alloc.vec.Vec fr8.Fr8) (values : _root_.Array Fr)
    (hsize : values.size = 4096) (hdata : DataRep (alloc.vec.Vec.deref data) values) :
    ∃ out, extension_kernel.ExtensionKernel.extend_loop0 kernel.shift data 0#usize = ok out ∧
      DataRep (alloc.vec.Vec.deref out) (shiftedValues values) := by
  have hlen : data.val.length = 512 := by
    have := hdata.1
    change values.size = 8 * data.val.length at this
    omega
  have hprefix : ShiftPrefix data values 0 := by
    refine ⟨hlen, ?_⟩
    intro v
    have hv : v.val < data.val.length := by omega
    simpa only [getElem!_pos data.val v.val hv, Nat.not_lt_zero, if_false]
      using hdata.2 ⟨v.val, hv⟩
  obtain ⟨out, hout, ho⟩ := shift_loop kernel hk values data 0#usize (by decide) hprefix
  refine ⟨out, hout, ?_, ?_⟩
  · simp only [shiftedValues, _root_.Array.size_ofFn, alloc.vec.Vec.deref, ho.1]
  · intro v
    have hv : v.val < 512 := by simpa only [alloc.vec.Vec.deref, ho.1] using v.isLt
    have hi (lane : Fin 8) : 8 * v.val + lane.val < 4096 := by omega
    simpa only [getElem!_pos out.val v.val v.isLt, hv, if_true,
      shiftedValues, _root_.Array.getElem!_ofFn, hi, _root_.dite_true]
      using ho.2 ⟨v.val, hv⟩

end LeanBlsSimd.Kzg.Extender.Kernel
