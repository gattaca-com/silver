import LeanBlsSimd.Kzg.InterpolationKernel.Basic
import LeanBlsSimd.Kzg.InterpolationKernel.Fr8Splat
import LeanBlsSimd.Kzg.InterpolationModel
import LeanBlsSimd.Kzg.Extender.Decode

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg
open scoped EthLib.Cryptography.Bls.Fr

attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero

namespace LeanBlsSimd.Kzg.InterpolationKernel

open Extender Extender.Kernel

private theorem decoded_value (b : ByteArray) (f : Fr)
    (h : (bytesToBlsField b).toOption = some f) : Fr.ofNat (Fr.bytesBEToNat b) = f := by
  by_cases hs : b.size = 32
  · by_cases hl : Fr.bytesBEToNat b < Fr.modulus
    · simp [bytesToBlsField, Constants.BYTES_PER_FIELD_ELEMENT, hs,
        Fr.fromBytesBE, hl, Except.toOption] at h
      subst f
      apply Fin.ext
      exact Nat.mod_eq_of_lt hl
    · simp [bytesToBlsField, Constants.BYTES_PER_FIELD_ELEMENT, hs, Fr.fromBytesBE, hl, Except.toOption] at h
  · simp [bytesToBlsField, Constants.BYTES_PER_FIELD_ELEMENT, hs, Except.toOption] at h

theorem cell_vector_refinement (cell : Array U8 2048#usize) (values : _root_.Array Fr)
    (hcell : CellRep cell values) (v : Usize) (hv : v.val < 8)
    (offset : Usize) (hoffset : offset.val = v.val * 256) :
    ∃ element mask,
      fr8.Fr8.from_bytes (Array.to_slice cell) offset = ok (element, mask) ∧
      Normalized element ∧
      ∀ lane : Fin 8, laneValue element lane = values[8 * v.val + lane.val]! := by
  obtain ⟨element, mask, hcall, hn, he, _⟩ := from_bytes_refinement
    (Array.to_slice cell) offset (by simp only [Array.to_slice, cell.property, UScalar.ofNatCore_val_eq]; omega)
  refine ⟨element, mask, hcall, hn, ?_⟩
  intro lane
  have hj : 8 * v.val + lane.val < 64 := by omega
  have hstart : offset.val + 32 * lane.val = 32 * (8 * v.val + lane.val) := by omega
  have hstop : offset.val + 32 * (lane.val + 1) = 32 * (8 * v.val + lane.val + 1) := by omega
  rw [laneValue, (he lane).1, hstart, hstop]
  exact decoded_value _ _ (hcell.2 ⟨8 * v.val + lane.val, hj⟩)

private theorem normalise_product (product : fr8.Fr8) (values : Fin 8 → Fr)
    (hp : LazyRep 2 32 product values) :
    ∃ normal, fr8.Fr8.normalise product = ok normal ∧ Represents normal values := by
  obtain ⟨normal, hcall, hn, he⟩ := normalise_lazy_refinement product values hp
    (by decide) (by decide)
  refine ⟨normal, hcall, ⟨hn, ?_⟩, fun lane => (he lane).2⟩
  intro lane
  have hb := (hp.1 lane).2.1
  rw [← (he lane).1] at hb
  exact_mod_cast hb

def weightedCell (old values : _root_.Array Fr) (power : Fr) : _root_.Array Fr :=
  _root_.Array.ofFn (n := 64) fun j => old[j.val]! + power * values[j.val]!

private def AddCellPrefix (data : alloc.vec.Vec fr8.Fr8) (column count : Nat)
    (first : Bool) (old values : _root_.Array Fr) (power : Fr) : Prop :=
  data.val.length = 1024 ∧ ∀ v : Fin 8,
    if v.val < count then
      Represents data.val[column * 8 + v.val]!
        (fun lane => (weightedCell old values power)[8 * v.val + lane.val]!)
    else first = false → Represents data.val[column * 8 + v.val]!
      (fun lane => old[8 * v.val + lane.val]!)

private theorem add_cell_loop (data : alloc.vec.Vec fr8.Fr8)
    (cell : Array U8 2048#usize) (column : Usize) (weight : fr8.Fr8)
    (first : Bool) (old values : _root_.Array Fr) (power : Fr)
    (hc : column.val < 128) (hcell : CellRep cell values)
    (hw : MultiplierRep weight (fun _ => power))
    (hzero : first = true → ∀ j : Fin 64, old[j.val]! = 0)
    (v : Usize) (hv : v.val ≤ 8) (hp : AddCellPrefix data column.val v.val first old values power) :
    ∃ out, interpolation_kernel.InterpolationKernel.add_cell_loop data cell column weight first v = ok out ∧
      AddCellPrefix out column.val 8 first old values power ∧
      ∀ i, i < column.val * 8 ∨ column.val * 8 + 8 ≤ i → out.val[i]! = data.val[i]! := by
  induction hrem : 8 - v.val generalizing data v with
  | zero =>
    have he : v.val = 8 := by omega
    refine ⟨data, ?_, by simpa only [he] using hp, fun _ _ => rfl⟩
    rw [interpolation_kernel.InterpolationKernel.add_cell_loop, loop.eq_1]
    simp only [interpolation_kernel.InterpolationKernel.add_cell_loop.body,
      vectors_per_cell_eq, bind_tc_ok, UScalar.lt_equiv, UScalar.ofNatCore_val_eq, he,
      lt_self_iff_false, if_false]
  | succ rem ih =>
    have hvt : v.val < 8 := by omega
    let offset : Usize := UScalar.ofNatCore (v.val * 256) (by scalar_tac)
    have hoffset : offset.val = v.val * 256 := UScalar.ofNatCore_val_eq _
    obtain ⟨element, mask, helement, hen, hev⟩ := cell_vector_refinement cell values hcell v hvt offset hoffset
    obtain ⟨product, hproduct, hpr⟩ := mul_multiplier_refinement element weight _ _ hen hev hw
    have hrep : ∃ result,
        (if first then fr8.Fr8.normalise product
         else fr8.Fr8.add data.val[column.val * 8 + v.val]! product) = ok result ∧
        Represents result (fun lane => (weightedCell old values power)[8 * v.val + lane.val]!) := by
      cases hf : first with
      | false =>
        have hold := hp.2 ⟨v.val, hvt⟩
        simp only [lt_self_iff_false, if_false, hf] at hold
        obtain ⟨result, hresult, hr⟩ := add_lazy_representation _ _ _ _ (hold True.intro).lazy hpr
          (by decide) (by decide)
        refine ⟨result, by simpa only [hf, Bool.false_eq_true, if_false] using hresult, ?_⟩
        refine ⟨hr.1, fun lane => ?_⟩
        rw [hr.2]
        simp [weightedCell, show 8 * v.val + lane.val < 64 by omega, mul_comm]
      | true =>
        obtain ⟨result, hresult, hr⟩ := normalise_product product _ hpr
        refine ⟨result, by simpa only [hf, if_true] using hresult, ?_⟩
        refine ⟨hr.1, fun lane => ?_⟩
        rw [hr.2]
        simp [weightedCell, show 8 * v.val + lane.val < 64 by omega,
          hzero hf ⟨8 * v.val + lane.val, by omega⟩, mul_comm]
    obtain ⟨result, hresult, hr⟩ := hrep
    let base : Usize := UScalar.ofNatCore (column.val * 8) (by scalar_tac)
    let index : Usize := UScalar.ofNatCore (column.val * 8 + v.val) (by scalar_tac)
    let v' : Usize := UScalar.ofNatCore (v.val + 1) (by scalar_tac)
    have hb : base.val = column.val * 8 := UScalar.ofNatCore_val_eq _
    have hi : index.val = column.val * 8 + v.val := UScalar.ofNatCore_val_eq _
    have hv' : v'.val = v.val + 1 := UScalar.ofNatCore_val_eq _
    have hil : index.val < data.val.length := by rw [hp.1, hi]; omega
    let next := alloc.vec.Vec.set data index result
    have hnext : AddCellPrefix next column.val v'.val first old values power := by
      refine ⟨by simpa [next, alloc.vec.Vec.set] using hp.1, ?_⟩
      intro j
      by_cases he : j.val = v.val
      · have hje : j = ⟨v.val, hvt⟩ := Fin.ext he
        subst j
        simpa [next, alloc.vec.Vec.set, hi, hv', List.getElem!_set, hp.1,
          show column.val * 8 + v.val < 1024 by omega] using hr
      · have hlt : (j.val < v'.val) = (j.val < v.val) := propext (by omega)
        simpa only [next, alloc.vec.Vec.set, hi,
          List.getElem!_set_ne data.val (column.val * 8 + v.val) (column.val * 8 + j.val) result (by omega), hlt]
          using hp.2 j
    have hindex : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice fr8.Fr8) data index =
        ok data.val[index.val]! := by
      simp [alloc.vec.Vec.index_usize, getElem!_pos, hil]
    have hmut : alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice fr8.Fr8) data index =
        ok (data.val[index.val]!, alloc.vec.Vec.set data index) := by
      simp [alloc.vec.Vec.index_mut_usize, alloc.vec.Vec.index_usize, getElem!_pos, hil]
    have hbody : interpolation_kernel.InterpolationKernel.add_cell_loop.body cell column weight first data v =
        ok (cont (next, v')) := by
      have hoff : v * 256#usize = ok offset := scalar_mul_ok v 256#usize (by scalar_tac)
      have hbase : column * 8#usize = ok base := scalar_mul_ok column 8#usize (by scalar_tac)
      have hadd : base + v = ok index := by simpa only [hb] using scalar_add_ok base v (by scalar_tac)
      have hinc : v + 1#usize = ok v' := scalar_add_ok v 1#usize (by scalar_tac)
      simp only [interpolation_kernel.InterpolationKernel.add_cell_loop.body,
        vectors_per_cell_eq, bind_tc_ok, UScalar.lt_equiv, UScalar.ofNatCore_val_eq, hvt, if_true,
        lift, bytes_per_vector_eq, hoff, helement, hproduct, hbase, hadd, hmut, hinc,
        Function.uncurry_apply_pair]
      cases first <;> simp only [Bool.false_eq_true, if_false, if_true] at hresult ⊢ <;>
        simp only [hindex, bind_tc_ok, hi, hresult, next]
    obtain ⟨out, hout, ho, hframe⟩ := ih next v' (by omega) hnext (by omega)
    refine ⟨out, ?_, ho, ?_⟩
    · rw [interpolation_kernel.InterpolationKernel.add_cell_loop, loop.eq_1]
      simpa only [hbody] using hout
    · intro i hiout
      rw [hframe i hiout]
      exact List.getElem!_set_ne data.val index.val i result (by omega)

theorem add_cell_refinement
    (kernel : interpolation_kernel.InterpolationKernel) (hk : StateInvariant kernel)
    (cell : Array U8 2048#usize) (column : Usize) (power : Fr)
    (values old : _root_.Array Fr) (hc : column.val < 128) (hcell : CellRep cell values)
    (hold : kernel.used.val[column.val]! = true → ∀ v : Fin 8,
      Represents kernel.columns.val[column.val * 8 + v.val]!
        (fun lane => old[8 * v.val + lane.val]!))
    (hzero : kernel.used.val[column.val]! = false → ∀ j : Fin 64, old[j.val]! = 0) :
    ∃ next, interpolation_kernel.InterpolationKernel.add_cell kernel cell column (frEncode power) = ok next ∧
      StateInvariant next ∧ SameTables kernel next ∧
      next.used.val = kernel.used.val.set column.val true ∧
      (∀ v : Fin 8, Represents next.columns.val[column.val * 8 + v.val]!
        (fun lane => (weightedCell old values power)[8 * v.val + lane.val]!)) ∧
      ∀ i, i < column.val * 8 ∨ column.val * 8 + 8 ≤ i →
        next.columns.val[i]! = kernel.columns.val[i]! := by
  obtain ⟨weight, hweight, hw⟩ := splat_multiplier_refinement power
  have hfirst : (!kernel.used.val[column.val]!) = true → ∀ j : Fin 64, old[j.val]! = 0 := by
    intro hf
    apply hzero
    simpa using hf
  have hp : AddCellPrefix kernel.columns column.val 0 (!kernel.used.val[column.val]!) old values power := by
    refine ⟨hk.2.2.1, ?_⟩
    intro v
    simp only [Nat.not_lt_zero, if_false]
    intro hf
    apply hold
    simpa using hf
  obtain ⟨columns, hloop, ho, hframe⟩ := add_cell_loop kernel.columns cell column weight
    (!kernel.used.val[column.val]!) old values power hc hcell hw hfirst 0#usize (by simp) hp
  let used := alloc.vec.Vec.set kernel.used column true
  let next := { kernel with columns := columns, used := used }
  have hindex : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice Bool) kernel.used column =
      ok kernel.used.val[column.val]! := by
    simp [alloc.vec.Vec.index_usize, getElem!_pos, hk.2.2.2.1, hc]
  have hmut : alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice Bool) kernel.used column =
      ok (kernel.used.val[column.val]!, alloc.vec.Vec.set kernel.used column) := by
    simp [alloc.vec.Vec.index_mut_usize, alloc.vec.Vec.index_usize, getElem!_pos, hk.2.2.2.1, hc]
  refine ⟨next, ?_, ?_, ⟨rfl, rfl⟩, rfl, ?_, hframe⟩
  · have hnot : decide (¬ kernel.used.val[column.val]! = true) = !kernel.used.val[column.val]! := by
      cases kernel.used.val[column.val]! <;> rfl
    simp only [interpolation_kernel.InterpolationKernel.add_cell,
      (multiplier_refinement power).1, bind_tc_ok, hweight, hindex, hmut,
      Function.uncurry_apply_pair, hnot, hloop, next, used]
  · exact ⟨hk.1, hk.2.1, ho.1, by simpa [next, used, alloc.vec.Vec.set] using hk.2.2.2.1,
      hk.2.2.2.2⟩
  · intro v
    simpa only [v.isLt, if_true] using ho.2 v

end LeanBlsSimd.Kzg.InterpolationKernel
