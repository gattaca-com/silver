import LeanBlsSimd.Kzg.PolynomialModel
import EthLib.Cryptography.Proofs.Kzg.CosetInterpolation

open EthLib.Cryptography Bls Kzg Kzg.BitReversal
open scoped EthLib.Cryptography.Bls.Fr

namespace LeanBlsSimd.Kzg

theorem getElem!_rootsOfUnityBrp_pow (n k i : Nat) (hn : n = 2 ^ k) (hi : i < n) :
    (rootsOfUnityBrp n)[i]! = domainRoot n ^ reverseBits i n := by
  have hb : i < (rootsOfUnityBrp n).size := by simpa only [size_rootsOfUnityBrp] using hi
  rw [getElem!_pos (rootsOfUnityBrp n) i hb, getElem_rootsOfUnityBrp hn]

theorem cellNodes_injective (c : Nat) (hc : c < 128) :
    Function.Injective (fun j : Fin 64 => (rootsOfUnityBrp 8192)[64 * c + j.val]!) := by
  obtain ⟨nodes, hnodes, hsize, hget⟩ := EthLib.Cryptography.Kzg.cosetForCell_ok_of_lt hc
  intro i j hij
  by_contra hne
  apply EthLib.Cryptography.Kzg.cosetForCell_distinct hnodes i.val j.val
    (by rw [hsize]; exact i.isLt) (by rw [hsize]; exact j.isLt)
    (Fin.val_ne_of_ne hne)
  rwa [hget i.val i.isLt, hget j.val j.isLt]

theorem cosetForCell_eq (c : Nat) (hc : c < 128) :
    cosetForCell c = .ok (Array.ofFn (fun j : Fin 64 => (rootsOfUnityBrp 8192)[64*c+j.val]!)) := by
  simp [cosetForCell, Constants.CELLS_PER_EXT_BLOB, Constants.FIELD_ELEMENTS_PER_CELL,
    Constants.FIELD_ELEMENTS_PER_EXT_BLOB, Constants.FIELD_ELEMENTS_PER_BLOB,
    show ¬128 ≤ c by omega, Pure.pure, Except.pure]

theorem size_cellIfft (c : Nat) (ys : Array Fr) : (cellIfft c ys).size = ys.size := by
  simp [cellIfft, size_bitReversalPermutation]

theorem getElem!_computeRootsOfUnity_pow (n i : Nat) (hi : i < n) :
    (computeRootsOfUnity n)[i]! = domainRoot n ^ i := by
  have hb : i < (computeRootsOfUnity n).size := by simpa only [size_computeRootsOfUnity] using hi
  rw [getElem!_pos (computeRootsOfUnity n) i hb, getElem_computeRootsOfUnity]

theorem interpolateCosetEvals_eq_cellIfft (c : Nat) (ys : Array Fr) (hys : ys.size = 64) :
    EthLib.Cryptography.Kzg.interpolateCosetEvals (Model.cosetShift c) ys =
      .ok (cellIfft c ys) := by
  unfold EthLib.Cryptography.Kzg.interpolateCosetEvals
  rw [show Constants.FIELD_ELEMENTS_PER_CELL = 64 from rfl, ite_eq_right (not_not.mpr hys)]
  rfl

theorem cellIfft_eval (c : Nat) (hc : c < 128) (ys : Array Fr) (hys : ys.size = 64)
    (j : Nat) (hj : j < 64) :
    (EthLib.Cryptography.Kzg.coefficientPolynomial (cellIfft c ys)).eval
      ((rootsOfUnityBrp 8192)[64 * c + j]!) = ys[j]! := by
  obtain ⟨p, hp, _, heval⟩ := EthLib.Cryptography.Kzg.interpolateCosetEvals_spec_of_ne_zero
    (h := Model.cosetShift c)
    (EthLib.Cryptography.Kzg.cosetShift_ne_zero c hc) hys
  rw [interpolateCosetEvals_eq_cellIfft c ys hys] at hp
  cases hp
  obtain ⟨nodes, hnodes, _, hget⟩ := EthLib.Cryptography.Kzg.cosetForCell_ok_of_lt hc
  rw [EthLib.Cryptography.Kzg.eval_coefficientPolynomial]
  change EthLib.Cryptography.Kzg.evalPolyAt (cellIfft c ys)
    ((rootsOfUnityBrp Constants.FIELD_ELEMENTS_PER_EXT_BLOB)[Constants.FIELD_ELEMENTS_PER_CELL * c + j]!) = _
  rw [← hget j hj,
    EthLib.Cryptography.Kzg.getElem!_cosetForCell_eq_shift_mul_root hnodes j hj]
  exact heval j hj

theorem cellIfft_interpolant (c : Nat) (hc : c < 128) (ys : Array Fr) (hys : ys.size = 64) :
    EthLib.Cryptography.Kzg.coefficientPolynomial (cellIfft c ys) =
      cellInterpolant c (fun j : Fin 64 => ys[j.val]!) := by
  unfold cellInterpolant
  apply Lagrange.eq_interpolate_of_eval_eq (fun j : Fin 64 => ys[j.val]!)
    ((cellNodes_injective c hc).injOn)
  · have hdeg : (EthLib.Cryptography.Kzg.coefficientPolynomial (cellIfft c ys)).degree <
        (cellIfft c ys).size := _root_.Polynomial.ofFn_degree_lt _
    simpa only [size_cellIfft, hys, Finset.card_univ, Fintype.card_fin] using hdeg
  · intro j _
    exact cellIfft_eval c hc ys hys j.val j.isLt

end LeanBlsSimd.Kzg
