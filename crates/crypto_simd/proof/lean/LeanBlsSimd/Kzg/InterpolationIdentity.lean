import LeanBlsSimd.Kzg.ColumnPolynomial
import LeanBlsSimd.Kzg.CosetPolynomial
import LeanBlsSimd.Kzg.PolynomialInterpolation

open EthCryptographySpecs Bls Kzg
open scoped EthCryptographySpecs.Bls.Fr

namespace LeanBlsSimd.Kzg

set_option maxHeartbeats 1000000
set_option maxRecDepth 4000

private theorem getElem!_ofFn_fr (f : Fin 64 → Fr) (j : Fin 64) :
    (Array.ofFn f)[j.val]! = f j := by
  rw [getElem!_pos (Array.ofFn f) j.val (by simp), Array.getElem_ofFn]

private theorem cell_interpolation (c : Nat) (hc : c < 128)
    (ys : Array Fr) (hys : ys.size = 64) :
    ∃ nodes out, cosetForCell c = .ok nodes ∧
      interpolatePolynomialcoeff nodes ys = .ok out ∧ out.size = 64 ∧
      coeffPolynomial out = cellInterpolant c (fun j => ys[j.val]!) := by
  let nodes := Array.ofFn (fun j : Fin 64 => (rootsOfUnityBrp 8192)[64*c+j.val]!)
  obtain ⟨out, hcall, hsize, hpoly⟩ := interpolatePolynomialcoeff_eq nodes ys
    (by simp [nodes]) hys
  refine ⟨nodes, out, cosetForCell_eq c hc, hcall, hsize, ?_⟩
  simpa only [nodes, getElem!_ofFn_fr, cellInterpolant] using hpoly

private def interpolationStep (indices : Array Nat) (evals : Array CosetEvals)
    (powers : Array Fr) (acc : Array Fr) (k : Nat) : Except KzgError (Array Fr) := do
  let interp ← interpolatePolynomialcoeff (← cosetForCell indices[k]!) evals[k]!
  let scaled ← multiplyPolynomialcoeff #[powers[k]!] interp
  pure (addPolynomialcoeff acc scaled)

private theorem interpolationStep_eq (indices : Array Nat) (evals : Array CosetEvals)
    (powers : Array Fr) (hs : Model.RliInputs indices evals powers)
    (k : Nat) (hk : k < indices.size) (acc : Array Fr) (ha : acc.size = 64) :
    ∃ out, interpolationStep indices evals powers acc k = .ok out ∧ out.size = 64 ∧
      coeffPolynomial out = coeffPolynomial acc +
        _root_.Polynomial.C powers[k]! * cellInterpolant indices[k]! (fun j => (evals[k]!)[j.val]!) := by
  have hc : indices[k]! < 128 := by
    rw [getElem!_pos indices k hk]
    exact hs.2.2.1 _ (Array.getElem_mem hk)
  have hkys : k < evals.size := by rw [← hs.1]; exact hk
  have hys : (evals[k]!).size = 64 := by
    rw [getElem!_pos evals k hkys]
    exact hs.2.2.2 _ (Array.getElem_mem hkys)
  obtain ⟨nodes, interp, hnodes, hcall, hisize, hipoly⟩ := cell_interpolation indices[k]! hc evals[k]! hys
  obtain ⟨scaled, hscale, hssize, hspoly⟩ := multiply_scalar64 powers[k]! interp hisize
  refine ⟨addPolynomialcoeff acc scaled, ?_, ?_, ?_⟩
  · unfold interpolationStep
    rw [hnodes]
    simp only [Bind.bind, Except.bind, hcall, hscale, Pure.pure, Except.pure]
  · simp only [size_addPolynomialcoeff, ha, hssize, max_self]
  · rw [coeffPolynomial_add, hspoly, _root_.Polynomial.smul_eq_C_mul, hipoly]

private theorem interpolation_fold (indices : Array Nat) (evals : Array CosetEvals)
    (powers : Array Fr) (hs : Model.RliInputs indices evals powers)
    (ks : List Nat) (hks : ∀ k ∈ ks, k < indices.size) (acc : Array Fr) (ha : acc.size = 64) :
    ∃ out, ks.foldlM (interpolationStep indices evals powers) acc = .ok out ∧ out.size = 64 ∧
      coeffPolynomial out = coeffPolynomial acc +
        (ks.map fun k => _root_.Polynomial.C powers[k]! *
          cellInterpolant indices[k]! (fun j => (evals[k]!)[j.val]!)).sum := by
  induction ks generalizing acc with
  | nil => exact ⟨acc, rfl, ha, by simp⟩
  | cons k ks ih =>
    obtain ⟨next, hnext, hnsize, hnpoly⟩ := interpolationStep_eq indices evals powers hs
      k (hks k (by simp)) acc ha
    obtain ⟨out, hout, hosize, hopoly⟩ := ih (fun k hk => hks k (by simp [hk])) next hnsize
    refine ⟨out, ?_, hosize, ?_⟩
    · rw [List.foldlM_cons, hnext]
      exact hout
    · rw [hopoly, hnpoly]
      simp only [List.map_cons, List.sum_cons, add_assoc]

theorem specRli_polynomial (indices : Array Nat) (evals : Array CosetEvals)
    (powers : Array Fr) (hs : Model.RliInputs indices evals powers) :
    ∃ out, Model.specRli indices evals powers = .ok out ∧ out.size = 64 ∧
      coeffPolynomial out = ∑ k ∈ Finset.range indices.size,
        _root_.Polynomial.C powers[k]! * cellInterpolant indices[k]! (fun j => (evals[k]!)[j.val]!) := by
  obtain ⟨out, hcall, hsize, hpoly⟩ := interpolation_fold indices evals powers hs
    (List.range indices.size) (fun _ hk => List.mem_range.mp hk) (Array.replicate 64 Fr.zero) (by simp)
  refine ⟨out, ?_, hsize, ?_⟩
  · simpa only [Model.specRli, ← Array.foldlM_toList, Array.toList_range, interpolationStep] using hcall
  · rw [hpoly, coeffPolynomial_replicate_zero, zero_add]
    simpa only [List.toFinset_range] using
      (List.sum_toFinset (fun k => _root_.Polynomial.C powers[k]! *
        cellInterpolant indices[k]! (fun j => (evals[k]!)[j.val]!))
        (List.nodup_range (n := indices.size))).symm

private theorem column_polynomial_size (indices : Array Nat) (evals : Array CosetEvals)
    (powers : Array Fr) (cs : List Nat) (acc : Array Fr) (ha : acc.size = 64) :
    (cs.foldl (fun total c => addPolynomialcoeff total
      (cellIfft c (columnValues indices evals powers c))) acc).size = 64 := by
  induction cs generalizing acc with
  | nil => exact ha
  | cons c cs ih =>
    apply ih
    simp only [size_addPolynomialcoeff, ha, size_cellIfft, columnValues_size, max_self]

theorem columnRli_size (indices : Array Nat) (evals : Array CosetEvals) (powers : Array Fr) :
    (Model.columnRli indices evals powers).size = 64 := by
  change ((Array.range 128).foldl (fun total c => addPolynomialcoeff total
    (cellIfft c (columnValues indices evals powers c))) (Array.replicate 64 Fr.zero)).size = 64
  rw [← Array.foldl_toList]
  exact column_polynomial_size _ _ _ _ _ (by simp)

theorem column_ifft_interpolation (indices : Array Nat) (evals : Array CosetEvals)
    (powers : Array Fr) (hs : Model.RliInputs indices evals powers) :
    Model.specRli indices evals powers = .ok (Model.columnRli indices evals powers) := by
  obtain ⟨out, hcall, hsize, hpoly⟩ := specRli_polynomial indices evals powers hs
  rw [hcall]
  congr 1
  apply coeffPolynomial_injective
  · rw [hsize, columnRli_size]
  · rw [hpoly, columnRli_polynomial cellIfft_interpolant indices evals powers hs.2.2.1]

end LeanBlsSimd.Kzg
