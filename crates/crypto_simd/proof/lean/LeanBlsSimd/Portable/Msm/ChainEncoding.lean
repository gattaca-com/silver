import LeanBlsSimd.Portable.Msm.ChainProducts
import LeanBlsSimd.Refines.Basic
import LeanBlsSimd.Portable.Fp.BatchInverse

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Msm.Batch
set_option maxRecDepth 4096

open BatchedRefines

def chainVector (values : ℕ → ChainField) (count : ℕ) : Vector ChainField 4 :=
  Vector.ofFn (chainValues values count)

def chainArray (values : ℕ → ChainField) (count : ℕ) : Array portable.fp.Fp 4#usize :=
  toArray (fun x : ChainField => (Kzg.fpEncode x).l) (chainVector values count)

def inverseArray (values : ℕ → ChainField) (count : ℕ) : Array portable.fp.Fp 4#usize :=
  toArray (fun x : ChainField => (Kzg.fpEncode x).l) ((chainVector values count).map (fun x : ChainField => x⁻¹))

theorem chainArray_index (values : ℕ → ChainField) (n : ℕ) (k : Usize) (hk : k.val < 4) :
    (chainArray values n).index_usize k = ok (Kzg.fpEncode (chainValues values n ⟨k.val,hk⟩)).l := by
  have h := index_usize_toArray (n := 4#usize) (m := 4)
    (fun x : ChainField => (Kzg.fpEncode x).l) (chainVector values n) rfl k hk
  simpa only [chainArray, chainVector, Vector.getElem_ofFn] using h

theorem chainVector_step (values : ℕ → ChainField) (i : ℕ) :
    (chainVector values i).set (i%4) (chainValues values i (chainKey i) * values i) (Nat.mod_lt _ (by decide)) =
      chainVector values (i+1) := by
  apply Vector.ext
  intro k hk
  simp only [chainVector, Vector.getElem_set, Vector.getElem_ofFn, chainValues, chainKey, Function.update_apply]
  by_cases h : i%4 = k
  · subst k
    simp
  · simp only [Fin.ext_iff] at *
    simp [h, Ne.symm h]

theorem chainArray_update (values : ℕ → ChainField) (i : ℕ) (k : Usize) (hk : k.val = i%4) :
    (chainArray values i).update k (Kzg.fpEncode (chainValues values i (chainKey i) * values i)).l =
      ok (chainArray values (i+1)) := by
  have hb : k.val < 4 := by rw [hk]; exact Nat.mod_lt _ (by decide)
  rw [chainArray, update_eq _ _ _ hb, set_toArray _ _ _ k _ hb]
  simp only [hk, chainVector_step]
  rfl

theorem encodeVector_four (v : Vector ChainField 4) :
    toArray (n := 4#usize) (fun x : ChainField => (Kzg.fpEncode x).l) v =
      Fp.encodeFour v[0] v[1] v[2] v[3] := by
  apply Subtype.ext
  apply List.ext_getElem
  · simp [toArray,Fp.encodeFour,Array.make]
  · intro i hi hj
    have hb : i < 4 := by simpa [toArray] using hi
    interval_cases i <;> simp [toArray,Fp.encodeFour,Array.make] <;> rfl

theorem batch_inverse_chains [RuntimeFeatures] (values : ℕ → ChainField) (n : ℕ)
    (hn : ∀ j < n, values j ≠ 0) :
    portable.msm.pairs.batch_inverse (chainArray values n) = ok (inverseArray values n) := by
  unfold chainArray inverseArray
  rw [encodeVector_four, encodeVector_four]
  simp only [chainVector, Vector.getElem_ofFn, Vector.getElem_map]
  exact Fp.batch_inverse_nonzero _ _ _ _
    (chainValues_nonzero values n hn 0) (chainValues_nonzero values n hn 1)
    (chainValues_nonzero values n hn 2) (chainValues_nonzero values n hn 3)

theorem inverseArray_index (values : ℕ → ChainField) (n : ℕ) (k : Usize) (hk : k.val < 4) :
    (inverseArray values n).index_usize k =
      ok (Kzg.fpEncode ((chainValues values n ⟨k.val,hk⟩)⁻¹ : ChainField)).l := by
  have h := index_usize_toArray (n := 4#usize) (m := 4)
    (fun x : ChainField => (Kzg.fpEncode x).l)
    ((chainVector values n).map (fun x : ChainField => x⁻¹)) rfl k hk
  simpa only [inverseArray,chainVector,Vector.getElem_map,Vector.getElem_ofFn] using h

theorem inverseVector_step (values : ℕ → ChainField) (i : ℕ)
    (hn : ∀ j < i+1, values j ≠ 0) :
    ((chainVector values (i+1)).map (fun x : ChainField => x⁻¹)).set (i%4)
      ((chainValues values (i+1) (chainKey i))⁻¹ * values i) (Nat.mod_lt _ (by decide)) =
      (chainVector values i).map (fun x : ChainField => x⁻¹) := by
  apply Vector.ext
  intro k hk
  simp only [Vector.getElem_set,Vector.getElem_map,chainVector,Vector.getElem_ofFn]
  by_cases h : i%4 = k
  · subst k
    simp only [if_pos rfl]
    exact advanced_inverse values i hn
  · rw [if_neg h,chainValues_step_ne values i ⟨k,hk⟩ h]

theorem inverseArray_update (values : ℕ → ChainField) (i : ℕ) (k : Usize) (hk : k.val = i%4)
    (hn : ∀ j < i+1, values j ≠ 0) :
    (inverseArray values (i+1)).update k
        (Kzg.fpEncode ((chainValues values (i+1) (chainKey i))⁻¹ * values i)).l =
      ok (inverseArray values i) := by
  have hb : k.val < 4 := by rw [hk]; exact Nat.mod_lt _ (by decide)
  rw [inverseArray,update_eq _ _ _ hb,set_toArray _ _ _ k _ hb]
  simp only [hk,inverseVector_step values i hn]
  rfl

theorem chainArray_zero (values : ℕ → ChainField) :
    chainArray values 0 = Array.repeat 4#usize portable.constants.ONE := by
  have hone : portable.constants.ONE = (Kzg.fpEncode (1 : Bls.Fp)).l :=
    Fp.rep_eq_encode Kzg.portableFpRep_one
  rw [chainArray,encodeVector_four]
  simp only [chainVector,Vector.getElem_ofFn,chainValues,hone]
  rfl

end LeanBlsSimd.Portable.Msm.Batch
