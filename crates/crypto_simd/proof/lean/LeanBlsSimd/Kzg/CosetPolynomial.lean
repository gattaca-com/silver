import LeanBlsSimd.Kzg.PolynomialModel
import LeanBlsSimd.Kzg.PolynomialArithmetic
import EthLib.Cryptography.Proofs.Kzg.Domain
import EthLib.Cryptography.Proofs.Kzg.FftInverse

open EthLib.Cryptography Bls Kzg Kzg.BitReversal
open scoped EthLib.Cryptography.Bls.Fr BigOperators

attribute [-instance] Fin.instNatPow

namespace LeanBlsSimd.Kzg

theorem reverseBits_cell_split (c j : Nat) (hj : j < 64) :
    reverseBits (64 * c + j) 8192 =
      128 * reverseBits j 64 + reverseBits c 128 := by
  change reverseBits (2 ^ 6 * c + j) (2 ^ 13) =
    2 ^ 7 * reverseBits j (2 ^ 6) + reverseBits c (2 ^ 7)
  have hj' : j < 2 ^ 6 := hj
  have hc' := reverseBits_lt_two_pow c 7
  apply Nat.eq_of_testBit_eq
  intro i
  rw [testBit_reverseBits, Nat.testBit_two_pow_mul_add _ hc']
  by_cases hi7 : i < 7
  · rw [ite_eq_left (by omega : i < 13), ite_eq_left hi7,
      Nat.testBit_two_pow_mul_add _ hj', ite_eq_right (by omega : ¬13 - 1 - i < 6),
      testBit_reverseBits, ite_eq_left hi7]
    congr 1
    omega
  · by_cases hi13 : i < 13
    · rw [ite_eq_left hi13, ite_eq_right hi7, Nat.testBit_two_pow_mul_add _ hj',
        ite_eq_left (by omega : 13 - 1 - i < 6), testBit_reverseBits,
        ite_eq_left (by omega : i - 7 < 6)]
      congr 1
      omega
    · rw [ite_eq_right hi13, ite_eq_right hi7, testBit_reverseBits,
        ite_eq_right (by omega : ¬i - 7 < 6)]

theorem domainRoot_8192_pow_128 : domainRoot 8192 ^ (128 : Nat) = domainRoot 64 := by
  unfold domainRoot
  rw [Fr.hpow_ofNat_eq_pow _ (by decide), Fr.hpow_ofNat_eq_pow _ (by decide),
    ← pow_mul]
  congr 1

theorem domainRoot_8192_primitive : IsPrimitiveRoot (domainRoot 8192) 8192 :=
  isPrimitiveRoot_domainRoot (Nat.dvd_of_mod_eq_zero (by decide))

theorem domainRoot_64_primitive : IsPrimitiveRoot (domainRoot 64) 64 :=
  isPrimitiveRoot_domainRoot (Nat.dvd_of_mod_eq_zero (by decide))

theorem getElem!_rootsOfUnityBrp_pow (n k i : Nat) (hn : n = 2 ^ k) (hi : i < n) :
    (rootsOfUnityBrp n)[i]! = domainRoot n ^ reverseBits i n := by
  have hb : i < (rootsOfUnityBrp n).size := by simpa only [size_rootsOfUnityBrp] using hi
  rw [getElem!_pos (rootsOfUnityBrp n) i hb, getElem_rootsOfUnityBrp hn]

theorem cellNode_layout (c : Nat) (hc : c < 128) (j : Nat) (hj : j < 64) :
    (rootsOfUnityBrp 8192)[64 * c + j]! =
      Model.cosetShift c * domainRoot 64 ^ reverseBits j 64 := by
  rw [getElem!_rootsOfUnityBrp_pow 8192 13 (64 * c + j) rfl (by omega),
    reverseBits_cell_split c j hj]
  unfold Model.cosetShift
  rw [getElem!_rootsOfUnityBrp_pow 8192 13 (64 * c) rfl (by omega)]
  have hzero : reverseBits (64 * c) 8192 = reverseBits c 128 := by
    have hz : reverseBits 0 64 = 0 := by decide
    simpa only [Nat.add_zero, hz, Nat.mul_zero, Nat.zero_add]
      using reverseBits_cell_split c 0 (by decide)
  rw [hzero, pow_add, pow_mul, domainRoot_8192_pow_128]
  exact mul_comm _ _

theorem cosetShift_ne_zero (c : Nat) (hc : c < 128) : Model.cosetShift c ≠ 0 := by
  unfold Model.cosetShift
  rw [getElem!_rootsOfUnityBrp_pow 8192 13 (64 * c) rfl (by omega)]
  exact pow_ne_zero _ (domainRoot_8192_primitive.ne_zero (by decide))

theorem cellNodes_injective (c : Nat) (hc : c < 128) :
    Function.Injective (fun j : Fin 64 => (rootsOfUnityBrp 8192)[64 * c + j.val]!) := by
  intro i j hij
  have h := getElem_rootsOfUnityBrp_inj (n := 8192) (k := 13) rfl
    (Nat.dvd_of_mod_eq_zero (by decide)) (by omega) (by omega) hij
  apply Fin.ext
  omega

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

theorem cellIfft_eval (c : Nat) (hc : c < 128) (ys : Array Fr) (hys : ys.size = 64)
    (j : Nat) (hj : j < 64) :
    (EthLib.Cryptography.Kzg.coefficientPolynomial (cellIfft c ys)).eval
      ((rootsOfUnityBrp 8192)[64 * c + j]!) = ys[j]! := by
  let vals := bitReversalPermutation ys
  let roots := computeRootsOfUnity 64
  let coeff := fftField vals roots true
  have hv : vals.size = 2 ^ 6 := by simpa only [vals, size_bitReversalPermutation] using! hys
  have hr : roots.size = 2 ^ 6 := size_computeRootsOfUnity 64
  have hcoeff : coeff.size = 2 ^ 6 := by simpa only [coeff, size_fftField] using hv
  have hroots : ∀ i, i < 2 ^ 6 → roots[i]! = domainRoot 64 ^ i :=
    fun i hi => getElem!_computeRootsOfUnity_pow 64 i hi
  have hround : fftField coeff roots false = vals :=
    fftField_inv_fftField (k := 6) domainRoot_64_primitive vals roots hv hr hroots
  have hrev : reverseBits j 64 < 2 ^ 6 := reverseBits_lt_two_pow j 6
  have hcancel : (Model.cosetShift c).inverse *
      (Model.cosetShift c * domainRoot 64 ^ reverseBits j 64) =
        domainRoot 64 ^ reverseBits j 64 := by
    rw [Fr.inverse_eq_inv]
    have hmul : (Model.cosetShift c)⁻¹ * Model.cosetShift c = (1 : Fr) :=
      inv_mul_cancel₀ (cosetShift_ne_zero c hc)
    calc
      _ = ((Model.cosetShift c)⁻¹ * Model.cosetShift c) *
          domainRoot 64 ^ reverseBits j 64 := (mul_assoc _ _ _).symm
      _ = _ := by rw [hmul]; exact one_mul _
  unfold cellIfft
  rw [EthLib.Cryptography.Kzg.eval_coefficientPolynomial,
    EthLib.Cryptography.Kzg.evalPolyAt_shiftVals, cellNode_layout c hc j hj, hcancel]
  change EthLib.Cryptography.Kzg.evalPolyAt coeff (domainRoot 64 ^ reverseBits j 64) = ys[j]!
  rw [← EthLib.Cryptography.Kzg.getElem!_fftField_eval (k := 6)
    domainRoot_64_primitive coeff roots hcoeff hr hroots _ hrev,
    hround]
  rw [getElem!_pos (bitReversalPermutation ys) (reverseBits j 64)
      (by simpa only [size_bitReversalPermutation, hys] using! hrev),
    getElem_bitReversalPermutation, hys, reverseBits_reverseBits (k := 6) hj]

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
