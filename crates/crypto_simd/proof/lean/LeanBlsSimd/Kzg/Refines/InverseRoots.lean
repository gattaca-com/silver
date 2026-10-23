import LeanBlsSimd.Kzg.Refines.Roots
import EthLib.Cryptography.Proofs.Kzg.Polynomials
import EthLib.Cryptography.Proofs.Kzg.Domain

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Refinement

attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero

private theorem inverse_loop (n : Usize) (roots : Slice blst.blst_fr) (target : List blst.blst_fr)
    (hrlen : roots.val.length = n.val) (htlen : target.length = n.val)
    (hlookup : ∀ j, 0 < j → j < n.val → roots.val[n.val-j]! = target[j]!)
    (acc : alloc.vec.Vec blst.blst_fr) (i : Usize) (hi : 0 < i.val ∧ i.val ≤ n.val)
    (ha : acc.val = target.take i.val) :
    ∃ out, domain.inverse_roots_loop roots n acc i = ok out ∧ out.val = target := by
  induction hk : n.val - i.val generalizing i acc with
  | zero =>
    have he : i.val = n.val := by omega
    refine ⟨acc, ?_, ?_⟩
    · rw [domain.inverse_roots_loop, loop.eq_1]
      simp [domain.inverse_roots_loop.body, UScalar.lt_equiv, he]
    · simpa [he, ← htlen] using ha
  | succ k ih =>
    have hil : i.val < n.val := by omega
    have hib : n.val < 2^UScalarTy.Usize.numBits := n.hBounds
    let j : Usize := UScalar.ofNatCore (n.val - i.val) (by omega)
    let i' : Usize := UScalar.ofNatCore (i.val + 1) (by omega)
    have hj : j.val = n.val - i.val := UScalar.ofNatCore_val_eq _
    have hi' : i'.val = i.val + 1 := UScalar.ofNatCore_val_eq _
    have hsub : n - i = ok j := by
      show UScalar.sub _ _ = _
      simp only [UScalar.sub, Nat.not_lt.mpr hi.2, if_false,
        Result.ok.injEq]
      apply (UScalar.eq_equiv_bv_eq _ _).mpr
      exact (UScalar.ofNatCore_bv _ _).symm
    have hadd : i + 1#usize = ok i' := by
      show UScalar.tryMk .Usize (i.val + (1#usize).val) = _
      simp [UScalar.tryMk, UScalar.tryMkOpt, Result.ofOption, i',
        show i.val + 1 < 2^System.Platform.numBits by change i.val + 1 < 2^UScalarTy.Usize.numBits; omega]
    have hindex : Slice.index_usize roots j = ok target[i.val]! := by
      rw [← hlookup _ hi.1 hil]
      simp [Slice.index_usize, hj, hrlen, show n.val-i.val < n.val by omega]
    have hsize : acc.val.length + 1 ≤ Usize.max := by
      rw [ha, List.length_take, htlen]
      have hnmax : n.val ≤ Usize.max := by scalar_tac
      omega
    let acc' : alloc.vec.Vec blst.blst_fr :=
      ⟨acc.val ++ [target[i.val]!], by simpa using hsize⟩
    have hpush : alloc.vec.Vec.push acc target[i.val]! = ok acc' := by
      simp [alloc.vec.Vec.push, hsize, acc']
    have ha' : acc'.val = target.take i'.val := by
      simp only [acc', ha, hi']
      rw [List.take_add_one, List.getElem?_eq_getElem (by omega : i.val < target.length)]
      simp only [getElem!_pos target i.val (by omega)]
      rfl
    obtain ⟨out, hout, hval⟩ := ih acc' i' (by omega) ha' (by omega)
    refine ⟨out, ?_, hval⟩
    rw [domain.inverse_roots_loop, loop.eq_1]
    simp only [domain.inverse_roots_loop.body, UScalar.lt_equiv,
      hil, if_true, hsub, hindex, hpush, hadd, bind_tc_ok]
    exact hout

theorem inverse_roots_refinement (n : Usize) (hn0 : 0 < n.val) (roots : Slice blst.blst_fr)
    (values : _root_.Array Fr) (hv : values.size = n.val)
    (hr : roots.val = values.toList.map frEncode) :
    ∃ out, domain.inverse_roots roots = ok out ∧
      out.val = (Model.inverseRoots values).toList.map frEncode := by
  let target := (Model.inverseRoots values).toList.map frEncode
  have hlen : roots.val.length = n.val := by simp [hr, hv]
  have htlen : target.length = n.val := by simp [target, Model.inverseRoots, hv]
  have htarget (j : Nat) (hj : j < n.val) :
      target[j]! = frEncode (if j = 0 then values[0]! else values[n.val-j]!) := by
    have htb : j < target.length := by omega
    rw [getElem!_pos target j htb]
    simp only [target, List.getElem_map, _root_.Array.getElem_toList,
      Model.inverseRoots, _root_.Array.getElem_ofFn, hv]
  have hlookup (j : Nat) (hj : j < n.val) : roots.val[j]! = frEncode values[j]! := by
    rw [hr, getElem!_pos _ j (by simp [hv]; omega)]
    simp [getElem!_pos values j (by omega)]
  have hzero : roots.val[0]! = target[0]! := by rw [hlookup 0 hn0, htarget 0 hn0]; rfl
  let initial : alloc.vec.Vec blst.blst_fr := ⟨[target[0]!], by simp; scalar_tac⟩
  have hinitial : initial.val = target.take (1#usize).val := by
    simp only [UScalar.ofNatCore_val_eq, initial]
    rw [show (1 : Nat) = 0 + 1 by rfl, List.take_add_one,
      List.getElem?_eq_getElem (by omega : 0 < target.length)]
    simp [getElem!_pos target 0 (by omega)]
  obtain ⟨out, hout, hval⟩ := inverse_loop n roots target hlen htlen
    (by
      intro j hj hjn
      rw [hlookup (n.val-j) (by omega), htarget j hjn, if_neg (by omega)])
    initial 1#usize (by change 0 < 1 ∧ 1 ≤ n.val; omega) hinitial
  refine ⟨out, ?_, hval⟩
  have hlength : Slice.len roots = n := by apply UScalar.eq_of_val_eq; simpa using hlen
  have hindex : Slice.index_usize roots 0#usize = ok target[0]! := by
    rw [← hzero]
    simp [Slice.index_usize,List.getElem?_eq_getElem (by omega : 0 < roots.val.length),
      getElem!_pos roots.val 0 (by omega)]
  have hpush : alloc.vec.Vec.push (alloc.vec.Vec.with_capacity blst.blst_fr n)
      target[0]! = ok initial := by
    simp [alloc.vec.Vec.push, alloc.vec.Vec.with_capacity, initial, U32.max_eq]
  unfold domain.inverse_roots
  dsimp only
  simp only [hlength, hindex, hpush, bind_tc_ok]
  exact hout


open scoped EthLib.Cryptography.Bls.Fr in
theorem inverse_roots_get_inverse (n : Nat) (hn : 0 < n)
    (hdvd : n ∣ Fr.modulus-1) (i : Nat) (hi : i < n) :
    (Model.inverseRoots (computeRootsOfUnity n))[i]! = ((computeRootsOfUnity n)[i]!).inverse := by
  have hsize : (computeRootsOfUnity n).size = n := by simp
  have hroot (j : Nat) (hj : j < n) :
      (computeRootsOfUnity n)[j]! = domainRoot n ^ j := by
    rw [getElem!_pos _ j (by simpa using hj), getElem_computeRootsOfUnity]
  have hprim : IsPrimitiveRoot (domainRoot n) n :=
    isPrimitiveRoot_domainRoot hdvd
  have hne : domainRoot n ≠ 0 := hprim.ne_zero (by omega)
  rw [getElem!_pos _ i (by simp [Model.inverseRoots, hsize]; omega)]
  simp only [Model.inverseRoots, _root_.Array.getElem_ofFn, hsize]
  by_cases hz : i = 0
  · simp [hz, hroot 0 (by omega), Fr.inverse_eq_inv]
  · rw [if_neg hz, hroot (n-i) (by omega), hroot i hi, Fr.inverse_eq_inv]
    have hp : domainRoot n ^ i * domainRoot n ^ (n-i) = 1 := by
      exact (pow_add (domainRoot n) i (n-i)).symm.trans
        (by rw [Nat.add_sub_of_le (by omega : i ≤ n)]; exact hprim.pow_eq_one)
    have hc : (domainRoot n ^ i)⁻¹ * domainRoot n ^ i = (1 : Fr) :=
      inv_mul_cancel₀ (pow_ne_zero i hne)
    calc
      domainRoot n ^ (n-i) = 1 * domainRoot n ^ (n-i) := (one_mul _).symm
      _ = ((domainRoot n ^ i)⁻¹ * domainRoot n ^ i) *
          domainRoot n ^ (n-i) := congrArg (fun x : Fr => x * _) hc.symm
      _ = (domainRoot n ^ i)⁻¹ * (domainRoot n ^ i *
          domainRoot n ^ (n-i)) := mul_assoc _ _ _
      _ = (domainRoot n ^ i)⁻¹ := by rw [hp]; exact mul_one _

end LeanBlsSimd.Kzg.Refinement
