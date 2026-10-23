import LeanBlsSimd.Kzg.Extender.Basic
import LeanBlsSimd.Kzg.Extender.Kernel.Fft
import LeanBlsSimd.Kzg.Extender.Kernel.Shift
import LeanBlsSimd.Kzg.Extender.Kernel.Decode
import LeanBlsSimd.Kzg.Extender.Kernel.Encode
import LeanBlsSimd.Kzg.Extender.Kernel.Construct
import LeanBlsSimd.Kzg.Extender.Write
import LeanBlsSimd.Kzg.Extender.Acceptance

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls Kzg Kzg.BitReversal
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel

theorem extend_refinement (kernel : extension_kernel.ExtensionKernel)
    (hk : StateInvariant kernel) (values : _root_.Array Fr) (hsize : values.size = 4096)
    (hdata : DataRep (alloc.vec.Vec.deref kernel.data) values) (cells : Cells) :
    ∃ next out, extension_kernel.ExtensionKernel.extend kernel cells = ok (next, out) ∧
      StateInvariant next ∧ SameTables kernel next ∧
      DataRep (alloc.vec.Vec.deref next.data) (bitReversalPermutation (Model.extension values)) ∧
      cellBytes out = extensionCells cells (bitReversalPermutation (Model.extension values)) ∧
      ∀ i : Fin 64, out.val[i.val]? = cells.val[i.val]? := by
  let inverseValues := fftFieldAux (bitReversalPermutation values)
    (Kzg.Model.inverseRoots (Kzg.Model.roots 12))
  have hiSize : inverseValues.size = 4096 := by
    simp only [inverseValues, size_fftFieldAux, size_bitReversalPermutation, hsize]
  obtain ⟨inverse, hinverse, hirep⟩ := dit_refinement kernel.inverse
    (alloc.vec.Vec.deref kernel.data) values (Kzg.Model.inverseRoots (Kzg.Model.roots 12)) hk.1
    (by simpa [Kzg.Model.inverseRoots, Kzg.Model.roots] using hsize)
    blob_roots_valid.2 hdata
  let inverseVec : alloc.vec.Vec fr8.Fr8 := ⟨inverse.val, inverse.property⟩
  obtain ⟨shifted, hshift, hsrep⟩ := shift_refinement kernel hk inverseVec inverseValues hiSize hirep
  obtain ⟨evaluations, hforward, herep⟩ := dif_refinement kernel.forward
    (alloc.vec.Vec.deref shifted) (shiftedValues inverseValues) (Kzg.Model.roots 12) hk.2.1
    (by simp only [shiftedValues, _root_.Array.size_ofFn, Kzg.Model.roots, size_computeRootsOfUnity])
    blob_roots_valid.1 hsrep
  have hmodel : fftFieldAux (shiftedValues inverseValues) (Kzg.Model.roots 12) =
      Model.extension values := by
    unfold Model.extension Kzg.Model.inverseFft
    apply congrArg (fun a => fftFieldAux a (Kzg.Model.roots 12))
    apply _root_.Array.ext
    · simp only [shiftedValues, _root_.Array.size_ofFn]
    · intro i hi hj
      have hil : i < inverseValues.size := by
        simpa only [shiftedValues, _root_.Array.size_ofFn, hiSize] using hi
      simp only [shiftedValues, _root_.Array.getElem_ofFn, shiftFactor]
      change inverseValues[i]! * ((Kzg.Model.roots 13)[i]! * (Fr.ofNat 4096).inverse) =
        (inverseValues.map (· * (Fr.ofNat 4096).inverse))[i]! * (Kzg.Model.roots 13)[i]!
      rw [getElem!_pos (inverseValues.map (· * (Fr.ofNat 4096).inverse)) i
          (by simpa only [_root_.Array.size_map] using hil),
        _root_.Array.getElem_map]
      rw [getElem!_pos inverseValues i hil]
      change inverseValues[i] * ((Kzg.Model.roots 13)[i]! * (Fr.ofNat 4096).inverse) =
        (inverseValues[i] * (Fr.ofNat 4096).inverse) * (Kzg.Model.roots 13)[i]!
      rw [Fr.mul_assoc, Fr.mul_comm (Fr.ofNat 4096).inverse]
  rw [hmodel] at herep
  have heSize : (bitReversalPermutation (Model.extension values)).size = 4096 := by
    simp only [Model.extension, size_bitReversalPermutation, size_fftFieldAux,
      _root_.Array.size_ofFn]
  let next : extension_kernel.ExtensionKernel :=
    { kernel with data := ⟨evaluations.val, evaluations.property⟩ }
  have hlen : next.data.val.length = 512 := by
    have h := herep.1
    rw [heSize] at h
    change 4096 = 8 * evaluations.val.length at h
    change evaluations.val.length = 512
    omega
  obtain ⟨out, hencode, hout, hframe⟩ := encode_refinement next.data
    (bitReversalPermutation (Model.extension values)) heSize herep cells
  refine ⟨next, out, ?_, ⟨hk.1, hk.2.1, hk.2.2.1, hlen, hk.2.2.2.2⟩,
    ⟨rfl, rfl, rfl⟩, herep, hout, hframe⟩
  simp only [extension_kernel.ExtensionKernel.extend, alloc.vec.Vec.deref_mut, lift,
    bind_tc_ok, Function.uncurry_apply_pair]
  simp only [alloc.vec.Vec.deref] at hinverse
  rw [hinverse]
  simp only [bind_tc_ok]
  change (do
    let shifted ← extension_kernel.ExtensionKernel.extend_loop0 kernel.shift inverseVec 0#usize
    let evaluations ← fft8.Fft8.dif kernel.forward (alloc.vec.Vec.deref shifted)
    let out ← extension_kernel.ExtensionKernel.extend_loop1
      ⟨evaluations.val, evaluations.property⟩ cells 0#usize
    ok ({ kernel with data := ⟨evaluations.val, evaluations.property⟩ }, out)) = _
  simp only [hshift, bind_tc_ok, hforward, hencode, next]

/-- The generated Some branch needs no correctness law for any external operation.
`compute` dispatches on the stored kernel without reading `simdAvailable`. -/
theorem compute_refinement
    (v : cell_extender.CellExtender) (hv : Extender.StateInvariant v)
    (kernel : extension_kernel.ExtensionKernel) (hkernel : v.kernel = some kernel)
    (blob : Blob) (cells : Cells) :
    ∃ (verdict : Bool) (next : cell_extender.CellExtender) (out : Cells),
      cell_extender.CellExtender.compute v blob cells = ok (verdict, next, out) ∧
      Extender.StateInvariant next ∧
      (verdict, cellBytes out) = Model.compute (arrayBytes blob) (cellBytes cells) ∧
      (verdict = false → out = cells) ∧
      ∃ nextKernel, next = { v with kernel := some nextKernel } ∧ SameTables kernel nextKernel := by
  have hk : StateInvariant kernel := by
    simpa only [hkernel] using hv.2.2.2.2.2.2
  have hstate (k : extension_kernel.ExtensionKernel) (hi : StateInvariant k) :
      Extender.StateInvariant { v with kernel := some k } :=
    ⟨hv.1, hv.2.1, hv.2.2.1, hv.2.2.2.1, hv.2.2.2.2.1, hv.2.2.2.2.2.1, hi⟩
  obtain ⟨verdict, decoded, hdecode, hdi, hdt, hcanonical, _, _, hvalues⟩ :=
    decode_refinement kernel hk blob
  cases verdict with
  | false =>
    have hnot : ¬ Canonical blob := by simpa using hcanonical.symm
    have herror : ∃ err, blobToPolynomial (arrayBytes blob) = .error err := by
      cases hb : blobToPolynomial (arrayBytes blob) with
      | error err => exact ⟨err, rfl⟩
      | ok values => exact (hnot ((blob_decode_exists_iff blob).mp ⟨values, hb⟩)).elim
    obtain ⟨err, herr⟩ := herror
    refine ⟨false, { v with kernel := some decoded }, cells, ?_, hstate decoded hdi,
      ?_, (fun _ => rfl), decoded, rfl, hdt⟩
    · simp only [cell_extender.CellExtender.compute, hkernel, hdecode, bind_tc_ok,
        Function.uncurry_apply_pair, Bool.false_eq_true, if_false]
    · simp [Model.compute, Model.extend, herr]
  | true =>
    obtain ⟨values, hblob, hdata⟩ := hvalues rfl
    have hsize : values.size = 4096 := by
      simpa only [alloc.vec.Vec.deref, hdi.2.2.2.1] using hdata.1
    obtain ⟨copied, hcopy, hcopied⟩ := copy_first_half blob cells
    obtain ⟨next, out, hextend, hn, ht, _, hout, _⟩ :=
      extend_refinement decoded hdi values hsize hdata copied
    refine ⟨true, { v with kernel := some next }, out, ?_, hstate next hn, ?_,
      (by simp), next, rfl, ht.1.trans hdt.1, ht.2.1.trans hdt.2.1, ht.2.2.trans hdt.2.2⟩
    · have hcount : CELLS_PER_EXT_BLOB = ok 128#usize := cells_per_ext_blob_eq
      have hhalf : 128#usize / 2#usize = ok 64#usize := rfl
      simp only [cell_extender.CellExtender.compute, hkernel, hdecode, bind_tc_ok,
        Function.uncurry_apply_pair, if_true, cell_extender.copy_blob, hcount, hhalf, hcopy, hextend]
    · simp only [Model.compute, Model.extend, hblob]
      change (true, cellBytes out) = (true, _)
      rw [hout]
      apply congrArg (fun xs : _root_.Array Cell => (true, xs))
      apply _root_.Array.ext
      · simp only [extensionCells, _root_.Array.size_ofFn]
      · intro i hi hj
        simp only [extensionCells, _root_.Array.getElem_ofFn]
        split
        · exact hcopied i (by assumption)
        · rfl

end LeanBlsSimd.Kzg.Extender.Kernel
