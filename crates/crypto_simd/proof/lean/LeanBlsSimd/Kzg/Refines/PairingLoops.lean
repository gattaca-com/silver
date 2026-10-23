import LeanBlsSimd.Kzg.Lincomb
import LeanBlsSimd.Kzg.PairingRepresentation
import LeanBlsSimd.Kzg.Refines.Roots
import LeanBlsSimd.Kzg.Refines.Interpolation
import LeanBlsSimd.Kzg.Refines.InterpolationCommitment

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls
open private LeanBlsSimd.Kzg.Refinement.powers_loop from LeanBlsSimd.Kzg.Refines.Roots

namespace LeanBlsSimd.Kzg.Pairing

set_option maxHeartbeats 4000000
set_option maxRecDepth 16000

theorem powers_loop [RuntimeFeatures] (h : ExternalsCorrect)
    (r power : Fr) (acc : alloc.vec.Vec blst.blst_fr) (iter : core.ops.range.Range Usize)
    (hi : iter.start.val ≤ iter.end.val)
    (hb : acc.val.length + (iter.end.val - iter.start.val) ≤ Usize.max) :
    ∃ out, verify.CellBatchVerifier.pairing_holds_loop0 iter acc (frEncode r) (frEncode power) =
      ok out ∧ out.val = acc.val ++
        (computePowersAux r power (iter.end.val - iter.start.val)).map frEncode :=
  LeanBlsSimd.Kzg.Refinement.powers_loop h.fr r power acc iter hi hb

private theorem index_encoded (v : alloc.vec.Vec blst.blst_fr) (xs : List Fr)
    (hv : v.val = xs.map frEncode) (i : Usize) (hi : i.val < xs.length) :
    alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice blst.blst_fr) v i =
      ok (frEncode xs[i.val]!) := by
  simp [alloc.vec.Vec.index_usize, hv, getElem!_pos, hi]

private theorem index_mut_encoded (v : alloc.vec.Vec blst.blst_fr) (xs : List Fr)
    (hv : v.val = xs.map frEncode) (i : Usize) (hi : i.val < xs.length) :
    alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice blst.blst_fr) v i =
      ok (frEncode xs[i.val]!, alloc.vec.Vec.set v i) := by
  simp [alloc.vec.Vec.index_mut_usize, alloc.vec.Vec.index_usize, hv, getElem!_pos, hi]

def weightStep (mapping : List Usize) (powers : List Fr) (weights : List Fr) (k : Nat) : List Fr :=
  weights.set mapping[k]!.val (weights[mapping[k]!.val]! + powers[k]!)

theorem weights_length (mapping : List Usize) (powers weights : List Fr) (ks : List Nat) :
    (ks.foldl (weightStep mapping powers) weights).length = weights.length := by
  induction ks generalizing weights with
  | nil => rfl
  | cons k ks ih => simpa [weightStep] using ih (weightStep mapping powers weights k)

theorem weights_model (mapping : List Usize) (powers : _root_.Array Fr) (count : Nat) :
    ((List.range mapping.length).foldl (weightStep mapping powers.toList)
      (List.replicate count Fr.zero)).toArray =
      (_root_.Array.range mapping.length).foldl (init := _root_.Array.replicate count Fr.zero)
        (fun weights k =>
          let i := (mapping.map (·.val)).toArray[k]!
          weights.set! i (weights[i]! + powers[k]!)) := by
  apply _root_.Array.toList_inj.mp
  simp only [← _root_.Array.foldl_toList, _root_.Array.toList_range]
  apply _root_.List.foldl_rel (r := fun (xs : List Fr) (ys : _root_.Array Fr) => xs = ys.toList) (by simp)
  intro k hk xs ys hxy
  have hkm : k < mapping.length := List.mem_range.mp hk
  have hmap : (mapping.map (·.val)).toArray[k]! = mapping[k]!.val := by
    simp [getElem!_pos, hkm]
  simp only [hmap, _root_.Array.set!_eq_setIfInBounds, _root_.Array.toList_setIfInBounds, weightStep, hxy,
    _root_.Array.getElem!_toList]

theorem weights_loop [RuntimeFeatures] (h : ExternalsCorrect)
    (mapping : alloc.vec.Vec Usize) (vp acc : alloc.vec.Vec blst.blst_fr)
    (powers weights : List Fr) (hp : vp.val = powers.map frEncode)
    (ha : acc.val = weights.map frEncode) (n : Nat)
    (hm : n ≤ mapping.val.length) (hnp : n ≤ powers.length)
    (hmi : ∀ i ∈ mapping.val, i.val < weights.length)
    (iter : core.ops.range.Range Usize) (hi : iter.start.val ≤ n) (he : iter.end.val = n) :
    ∃ result, verify.CellBatchVerifier.pairing_holds_loop1 iter mapping vp acc = ok result ∧
      result.val = (((List.range n).drop iter.start.val).foldl
        (weightStep mapping.val powers) weights).map frEncode := by
  induction hk : n - iter.start.val generalizing iter acc weights with
  | zero =>
    have hs : iter.start.val = n := by omega
    have hnext := Refinement.next_ge iter (by omega)
    refine ⟨acc, ?_, by simpa [hs] using ha⟩
    rw [verify.CellBatchVerifier.pairing_holds_loop1, loop.eq_1]
    simp only [verify.CellBatchVerifier.pairing_holds_loop1.body, hnext,
      bind_tc_ok, Function.uncurry_apply_pair]
  | succ k ih =>
    have hj : iter.start.val < n := by omega
    obtain ⟨iter', hs', he', hnext⟩ := Refinement.next_lt iter (by omega)
    have hjm : iter.start.val < mapping.val.length := by omega
    let i := mapping.val[iter.start.val]!
    have hindex : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice Usize)
        mapping iter.start = ok i := by
      simp [alloc.vec.Vec.index_usize, getElem!_pos, hjm, i]
    have himem : i ∈ mapping.val := by
      simp only [i, getElem!_pos mapping.val iter.start.val hjm]
      exact List.getElem_mem hjm
    have hib : i.val < weights.length := hmi i himem
    have hweight := index_encoded acc weights ha i hib
    have hpower := index_encoded vp powers hp iter.start (by omega)
    have hmut := index_mut_encoded acc weights ha i hib
    let acc' := alloc.vec.Vec.set acc i (frEncode (weights[i.val]! + powers[iter.start.val]!))
    have ha' : acc'.val = (weightStep mapping.val powers weights iter.start.val).map frEncode := by
      simp [acc', alloc.vec.Vec.set, ha, weightStep, i]
    have hbody : verify.CellBatchVerifier.pairing_holds_loop1.body mapping vp iter acc =
        ok (cont (iter', acc')) := by
      simp only [verify.CellBatchVerifier.pairing_holds_loop1.body, hnext,
        bind_tc_ok, Function.uncurry_apply_pair, hindex, hweight, hpower,
        h.fr.fr_add, hmut, acc']
    obtain ⟨result, hloop, hr⟩ := ih acc'
      (weightStep mapping.val powers weights iter.start.val) ha'
      (by simpa [weightStep] using hmi) iter' (by omega)
      (by simpa only [he'] using he) (by omega)
    refine ⟨result, ?_, ?_⟩
    · rw [verify.CellBatchVerifier.pairing_holds_loop1, loop.eq_1]
      simp only [hbody]
      exact hloop
    · rw [List.drop_eq_getElem_cons (by simp [hj])]
      simpa only [List.foldl_cons, List.getElem_range, hs'] using hr

def shiftedScalar (indices : List U64) (powers : List Fr) (k : Nat) : Fr :=
  powers[k]! * Fr.powNat (Model.cosetShift indices[k]!.val) 64

theorem shifted_model (indices : List U64) (powers : _root_.Array Fr)
    (hlen : indices.length ≤ powers.size) :
    ((List.range indices.length).map (shiftedScalar indices powers.toList)).toArray =
      (_root_.Array.range indices.length).map (fun k => powers[k]! *
        Fr.powNat (Model.cosetShift (indices.map (·.val)).toArray[k]!) 64) := by
  apply _root_.Array.toList_inj.mp
  simp only [_root_.Array.toList_map, _root_.Array.toList_range]
  apply List.map_congr_left
  intro k hk
  have hki : k < indices.length := List.mem_range.mp hk
  have hkp : k < powers.size := by omega
  simp [shiftedScalar, getElem!_pos, hki, hkp]

theorem shifts_loop [RuntimeFeatures] (h : ExternalsCorrect)
    (c : cosets.Cosets) (hc : CosetsRep c) (vp acc : alloc.vec.Vec blst.blst_fr)
    (powers : List Fr) (hp : vp.val = powers.map frEncode) (indices : Slice U64)
    (hnp : indices.val.length ≤ powers.length) (hindices : ∀ i ∈ indices.val, i.val < 128)
    (iter : core.ops.range.Range Usize) (hi : iter.start.val ≤ indices.val.length)
    (he : iter.end.val = indices.val.length)
    (hb : acc.val.length + (indices.val.length - iter.start.val) ≤ Usize.max) :
    ∃ out, verify.CellBatchVerifier.pairing_holds_loop2 iter c vp acc indices = ok (c, out) ∧
      out.val = acc.val ++ (((List.range indices.val.length).drop iter.start.val).map
        (shiftedScalar indices.val powers)).map frEncode := by
  induction hk : indices.val.length - iter.start.val generalizing iter acc with
  | zero =>
    have hs : iter.start.val = indices.val.length := by omega
    have hnext := Refinement.next_ge iter (by omega)
    refine ⟨acc, ?_, by simp [hs]⟩
    rw [verify.CellBatchVerifier.pairing_holds_loop2, loop.eq_1]
    simp only [verify.CellBatchVerifier.pairing_holds_loop2.body, hnext,
      bind_tc_ok, Function.uncurry_apply_pair]
  | succ k ih =>
    have hj : iter.start.val < indices.val.length := by omega
    obtain ⟨iter', hs', he', hnext⟩ := Refinement.next_lt iter (by omega)
    let raw := indices.val[iter.start.val]'hj
    have hraw : raw.val < 128 := hindices raw (List.getElem_mem hj)
    let i : Usize := UScalar.cast .Usize raw
    have hiv : i.val = raw.val := by
      rw [UScalar.cast_val_eq]
      apply Nat.mod_eq_of_lt
      scalar_tac
    have hindex : Slice.index_usize indices iter.start = ok raw := by
      simp [Slice.index_usize, hj, raw]
    have hshift : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice blst.blst_fr)
        c.shift_pow_cell i = ok (frEncode (Fr.powNat (Model.cosetShift raw.val) 64)) := by
      simp [alloc.vec.Vec.index_usize, hc.2.2.2, hiv, hraw]
    have hpower := index_encoded vp powers hp iter.start (by omega)
    let x := shiftedScalar indices.val powers iter.start.val
    have hx : x = powers[iter.start.val]! * Fr.powNat (Model.cosetShift raw.val) 64 := by
      simp only [x, shiftedScalar, getElem!_pos indices.val iter.start.val hj, raw]
    have hlen : acc.val.length + 1 ≤ Usize.max := by omega
    let acc' : alloc.vec.Vec blst.blst_fr := ⟨acc.val ++ [frEncode x], by simpa using hlen⟩
    have hpush : alloc.vec.Vec.push acc (frEncode x) = ok acc' := by
      simp [alloc.vec.Vec.push, hlen, acc']
    have hbody : verify.CellBatchVerifier.pairing_holds_loop2.body c vp indices iter acc =
        ok (cont (iter', acc')) := by
      simp only [verify.CellBatchVerifier.pairing_holds_loop2.body, hnext,
        bind_tc_ok, Function.uncurry_apply_pair, hindex, lift, hshift, hpower,
        h.fr.fr_mul, ← hx, hpush, i]
    obtain ⟨out, hloop, hout⟩ := ih acc' iter' (by omega) (by simpa only [he'] using he)
      (by simp only [acc', List.length_append, List.length_singleton]; omega) (by omega)
    refine ⟨out, ?_, ?_⟩
    · rw [verify.CellBatchVerifier.pairing_holds_loop2, loop.eq_1]
      simp only [hbody]
      exact hloop
    · have hdrop : (List.range indices.val.length).drop iter.start.val =
          iter.start.val :: (List.range indices.val.length).drop (iter.start.val + 1) := by
        rw [List.drop_eq_getElem_cons (by simp [hj])]
        simp only [List.getElem_range]
      rw [hout, hdrop]
      simp only [List.map_cons, hs', acc', x, List.append_assoc,
        List.singleton_append]

private theorem bind_ok_exists {α β : Type} (x : Result α) (f : α → Result β) (y : β)
    (h : (do let a ← x; f a) = ok y) : ∃ a, x = ok a ∧ f a = ok y := by
  cases x with
  | ok a => exact ⟨a, rfl, h⟩
  | fail err => cases h
  | div => cases h

theorem interpolation_frame [RuntimeFeatures]
    (v next : verify.CellBatchVerifier) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize)) (point : blst.blst_p1)
    (hrun : verify.CellBatchVerifier.interpolation_commitment v indices cells = ok (point, next)) :
    next.r_powers = v.r_powers ∧ next.proof_points = v.proof_points := by
  unfold verify.CellBatchVerifier.interpolation_commitment at hrun
  cases hk : v.kernel with
  | none =>
    simp only [hk] at hrun
    obtain ⟨columns0, _, hrun⟩ := bind_ok_exists _ _ _ hrun
    obtain ⟨cells, _, hrun⟩ := bind_ok_exists _ _ _ hrun
    obtain ⟨total, _, hrun⟩ := bind_ok_exists _ _ _ hrun
    obtain ⟨columns1, _, hrun⟩ := bind_ok_exists _ _ _ hrun
    obtain ⟨used0, _, hrun⟩ := bind_ok_exists _ _ _ hrun
    obtain ⟨used1, _, hrun⟩ := bind_ok_exists _ _ _ hrun
    obtain ⟨⟨columns, used⟩, _, hrun⟩ := bind_ok_exists _ _ _ hrun
    obtain ⟨interpolation0, _, hrun⟩ := bind_ok_exists _ _ _ hrun
    obtain ⟨interpolation1, _, hrun⟩ := bind_ok_exists _ _ _ hrun
    obtain ⟨column0, _, hrun⟩ := bind_ok_exists _ _ _ hrun
    obtain ⟨coefficients0, _, hrun⟩ := bind_ok_exists _ _ _ hrun
    obtain ⟨⟨cosets, column, coefficients, interpolation⟩, _, hrun⟩ := bind_ok_exists _ _ _ hrun
    obtain ⟨⟨point', scratch⟩, _, hrun⟩ := bind_ok_exists _ _ _ hrun
    cases hrun
    exact ⟨rfl, rfl⟩
  | some kernel =>
    simp only [hk] at hrun
    obtain ⟨interpolation, _, hrun⟩ := bind_ok_exists _ _ _ hrun
    simp only [lift, bind_tc_ok, alloc.vec.Vec.deref_mut, Function.uncurry_apply_pair] at hrun
    obtain ⟨⟨nextKernel, output⟩, _, hrun⟩ := bind_ok_exists _ _ _ hrun
    obtain ⟨⟨point', scratch⟩, _, hrun⟩ := bind_ok_exists _ _ _ hrun
    cases hrun
    exact ⟨rfl, rfl⟩

theorem resize_fields (v : alloc.vec.Vec blst.blst_fr) (n : Usize) (x : blst.blst_fr) :
    ∃ out, alloc.vec.Vec.resize blst.blst_fr.Insts.CoreCloneClone v n x = ok out ∧
      out.val = v.val.resize n.val x := by
  apply WP.spec_imp_exists
  apply alloc.vec.Vec.resize_spec
  simp [blst.blst_fr.Insts.CoreCloneClone.clone]

def InterpolationCorrect [RuntimeFeatures] : Prop :=
  ∀ (v : verify.CellBatchVerifier), StateInvariant v → ∀ (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (evals : _root_.Array CosetEvals) (powers : _root_.Array Fr),
    Model.RliInputs (indices.val.map (·.val)).toArray evals powers →
    indices.val.length * 2048 ≤ Isize.max.toNat →
    InterpolationKernel.CellsRep cells evals →
    (v.kernel = none → v.evaluations.val = (evals.toList.flatMap _root_.Array.toList).map frEncode) →
    v.r_powers.val = powers.toList.map frEncode →
    ∃ point next, verify.CellBatchVerifier.interpolation_commitment v indices cells = ok (point, next) ∧
      StateInvariant next ∧
      G1Rep point (G1.msm (rustG1Bytes.map (fun b => (specPoint b).getD G1.zero))
        (Model.columnRli (indices.val.map (·.val)).toArray evals powers))

end LeanBlsSimd.Kzg.Pairing
