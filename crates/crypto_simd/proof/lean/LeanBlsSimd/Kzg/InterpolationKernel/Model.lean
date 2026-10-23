import LeanBlsSimd.Kzg.InterpolationKernel.Column
import LeanBlsSimd.Kzg.InterpolationModel

open EthLib.Cryptography Bls Kzg Kzg.BitReversal
open scoped EthLib.Cryptography.Bls.Fr

attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero

namespace LeanBlsSimd.Kzg.InterpolationKernel

private theorem inverse_coefficients (values : Array Fr) (hsize : values.size = 64) :
    fftField (bitReversalPermutation values) (computeRootsOfUnity 64) true =
      (columnCoefficients values).map (· * (Fr.ofNat 64).inverse) := by
  simp only [fftField_def, if_true, size_bitReversalPermutation, hsize,
    columnCoefficients, Model.inverseRoots, Model.roots]

theorem columnStep_eq_totalStep (columns total : List Fr) (used : List Bool) (c : Nat)
    (ht : total.length = 64) (hu : used[c]! = true) :
    columnStep c total.toArray (Interpolation.columnView columns c) =
      (Interpolation.totalStep columns used total c).toArray := by
  simp only [Interpolation.totalStep, hu, if_true]
  rw [Interpolation.shiftAdd_eq _ _ _ (by
    simp only [Array.length_toList, size_fftField, List.size_toArray,
      Interpolation.reversedColumn_length, ht])]
  simp only [Array.toArray_toList, Interpolation.reversedColumn_eq]
  rw [inverse_coefficients _ (Interpolation.columnView_size columns c)]
  let coeffs := columnCoefficients (Interpolation.columnView columns c)
  have hcoeffs : coeffs.size = 64 := by
    simp only [coeffs, columnCoefficients, size_fftFieldAux,
      size_bitReversalPermutation, Interpolation.columnView_size]
  have hshift : (shiftVals (coeffs.map (· * (Fr.ofNat 64).inverse))
      (Model.cosetShift c).inverse).size = 64 := by
    simp only [size_shiftVals, Array.size_map, hcoeffs]
  change columnStep c total.toArray (Interpolation.columnView columns c) =
    addPolynomialcoeff total.toArray
      (shiftVals (coeffs.map (· * (Fr.ofNat 64).inverse)) (Model.cosetShift c).inverse)
  unfold columnStep addPolynomialcoeff
  rw [if_pos (by simp only [hshift, List.size_toArray, ht]; exact le_rfl)]
  apply Array.ext
  · simp only [Array.size_ofFn, List.size_toArray, ht]
  · intro i hi hi'
    have hi64 : i < 64 := by simpa only [Array.size_ofFn] using hi
    simp only [Array.getElem_ofFn, hshift, hi64, if_true]
    rw [getElem!_pos (shiftVals (coeffs.map (· * (Fr.ofNat 64).inverse))
        (Model.cosetShift c).inverse) i (by rw [hshift]; exact hi64), getElem_shiftVals,
      Array.getElem_map]
    rw [← getElem!_pos coeffs i (by rw [hcoeffs]; exact hi64)]
    simp only [coeffs, shiftFactor, Fr.powNat_eq_pow, mul_assoc]

end LeanBlsSimd.Kzg.InterpolationKernel
