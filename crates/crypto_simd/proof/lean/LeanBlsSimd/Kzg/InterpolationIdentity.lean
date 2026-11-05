import LeanBlsSimd.Kzg.ColumnPolynomial
import LeanBlsSimd.Kzg.CosetPolynomial

open EthLib.Cryptography Bls Kzg
open scoped EthLib.Cryptography.Bls.Fr

namespace LeanBlsSimd.Kzg

private def specRliFoldStep (indices : Array Nat) (evals : Array CosetEvals)
    (powers : Array Fr) (acc : Array Fr) (k : Nat) : Except KzgError (Array Fr) := do
  let interp ← EthLib.Cryptography.Kzg.interpolateCosetEvals
    (indices.map Model.cosetShift)[k]! evals[k]!
  let scaled ← multiplyPolynomialcoeff #[powers[k]!] interp
  pure (addPolynomialcoeff acc scaled)

private theorem specRliFoldStep_eq (indices : Array Nat) (evals : Array CosetEvals)
    (powers : Array Fr) (hs : Model.RliInputs indices evals powers)
    (k : Nat) (hk : k < indices.size) (acc : Array Fr) (ha : acc.size = 64) :
    ∃ out, specRliFoldStep indices evals powers acc k = .ok out ∧ out.size = 64 ∧
      EthLib.Cryptography.Kzg.coefficientPolynomial out =
        EthLib.Cryptography.Kzg.coefficientPolynomial acc +
        _root_.Polynomial.C powers[k]! * cellInterpolant indices[k]! (fun j => (evals[k]!)[j.val]!) := by
  have hc : indices[k]! < 128 := by
    rw [getElem!_pos indices k hk]
    exact hs.2.2.1 _ (Array.getElem_mem hk)
  have hkys : k < evals.size := by rw [← hs.1]; exact hk
  have hys : (evals[k]!).size = 64 := by
    rw [getElem!_pos evals k hkys]
    exact hs.2.2.2 _ (Array.getElem_mem hkys)
  have hshift : (indices.map Model.cosetShift)[k]! = Model.cosetShift indices[k]! := by
    rw [getElem!_pos _ k (by simpa using hk), Array.getElem_map, ← getElem!_pos indices k hk]
  obtain ⟨scaled, hscale, hssize⟩ := EthLib.Cryptography.Kzg.multiplyPolynomialcoeff_ok_of_le
    (a := #[powers[k]!]) (b := cellIfft indices[k]! evals[k]!)
    (by simp only [Array.size_singleton, size_cellIfft, hys]; decide)
  have hssize' : scaled.size = 64 := by
    simpa only [Array.isEmpty_iff_size_eq_zero, Array.size_singleton, Nat.one_ne_zero,
      ite_false, size_cellIfft, hys, Nat.reduceAdd, Nat.reduceSub,
      Nat.max_eq_left (by decide : 1 ≤ 64)] using hssize
  have hspoly : EthLib.Cryptography.Kzg.coefficientPolynomial scaled =
      cellInterpolant indices[k]! (fun j => powers[k]! * (evals[k]!)[j.val]!) := by
    unfold cellInterpolant
    apply Lagrange.eq_interpolate_of_eval_eq _ ((cellNodes_injective indices[k]! hc).injOn)
    · have hdeg : (EthLib.Cryptography.Kzg.coefficientPolynomial scaled).degree < scaled.size :=
        _root_.Polynomial.ofFn_degree_lt _
      simpa only [hssize', Finset.card_univ, Fintype.card_fin] using hdeg
    · intro j _
      rw [EthLib.Cryptography.Kzg.eval_coefficientPolynomial,
        EthLib.Cryptography.Kzg.evalPolyAt_mulPoly _ hscale,
        ← EthLib.Cryptography.Kzg.eval_coefficientPolynomial #[powers[k]!] _,
        coefficientPolynomial_singleton, _root_.Polynomial.eval_C,
        ← EthLib.Cryptography.Kzg.eval_coefficientPolynomial (cellIfft indices[k]! evals[k]!) _,
        cellIfft_eval indices[k]! hc evals[k]! hys j.val j.isLt]
  refine ⟨addPolynomialcoeff acc scaled, ?_, ?_, ?_⟩
  · delta specRliFoldStep
    rw [hshift, interpolateCosetEvals_eq_cellIfft indices[k]! evals[k]! hys]
    simp only [Bind.bind, Except.bind, hscale, Pure.pure, Except.pure]
  · simp only [size_addPolynomialcoeff, ha, hssize', max_self]
  · rw [coefficientPolynomial_add, hspoly, cellInterpolant_mul]

private theorem specRli_fold (indices : Array Nat) (evals : Array CosetEvals)
    (powers : Array Fr) (hs : Model.RliInputs indices evals powers)
    (ks : List Nat) (hks : ∀ k ∈ ks, k < indices.size) (acc : Array Fr) (ha : acc.size = 64) :
    ∃ out, ks.foldlM (specRliFoldStep indices evals powers) acc = .ok out ∧ out.size = 64 ∧
      EthLib.Cryptography.Kzg.coefficientPolynomial out =
        EthLib.Cryptography.Kzg.coefficientPolynomial acc +
        (ks.map fun k => _root_.Polynomial.C powers[k]! *
          cellInterpolant indices[k]! (fun j => (evals[k]!)[j.val]!)).sum := by
  induction ks generalizing acc with
  | nil => exact ⟨acc, rfl, ha, by simp⟩
  | cons k ks ih =>
    obtain ⟨next, hnext, hnsize, hnpoly⟩ := specRliFoldStep_eq indices evals powers hs
      k (hks k (by simp)) acc ha
    obtain ⟨out, hout, hosize, hopoly⟩ := ih (fun k hk => hks k (by simp [hk])) next hnsize
    refine ⟨out, ?_, hosize, ?_⟩
    · rw [List.foldlM_cons, hnext]
      exact hout
    · rw [hopoly, hnpoly]
      simp only [List.map_cons, List.sum_cons, add_assoc]

theorem specRli_polynomial (indices : Array Nat) (evals : Array CosetEvals)
    (powers : Array Fr) (hs : Model.RliInputs indices evals powers) :
    ∃ out, Model.specRli indices (indices.map Model.cosetShift) evals powers = .ok out ∧
      out.size = 64 ∧
      EthLib.Cryptography.Kzg.coefficientPolynomial out = ∑ k ∈ Finset.range indices.size,
        _root_.Polynomial.C powers[k]! * cellInterpolant indices[k]! (fun j => (evals[k]!)[j.val]!) := by
  obtain ⟨out, hcall, hsize, hpoly⟩ := specRli_fold indices evals powers hs
    (List.range indices.size) (fun _ hk => List.mem_range.mp hk) (Array.replicate 64 Fr.zero) (by simp)
  refine ⟨out, ?_, hsize, ?_⟩
  · change (Array.range indices.size).foldlM (specRliFoldStep indices evals powers)
      (Array.replicate 64 Fr.zero) = .ok out
    rw [← Array.foldlM_toList, Array.toList_range]
    exact hcall
  · rw [hpoly, coefficientPolynomial_replicate_zero, zero_add]
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

end LeanBlsSimd.Kzg
