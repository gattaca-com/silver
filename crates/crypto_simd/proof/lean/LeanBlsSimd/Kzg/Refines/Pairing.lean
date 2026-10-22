import LeanBlsSimd.Kzg.Lincomb
import LeanBlsSimd.Kzg.PairingRepresentation
import LeanBlsSimd.Kzg.Refines.Roots
import LeanBlsSimd.Kzg.Refines.Interpolation
import LeanBlsSimd.Kzg.Refines.InterpolationCommitment

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls
open private LeanBlsSimd.Kzg.Refinement.powers_loop from LeanBlsSimd.Kzg.Refines.Roots

namespace LeanBlsSimd.Kzg.Pairing

set_option maxHeartbeats 4000000
set_option maxRecDepth 16000

theorem powers_loop [e : KzgExternals] (h : ExternalsCorrect e)
    (r power : Fr) (acc : alloc.vec.Vec blst.blst_fr) (iter : core.ops.range.Range Usize)
    (hi : iter.start.val ≤ iter.end.val)
    (hb : acc.val.length + (iter.end.val - iter.start.val) ≤ Usize.max) :
    ∃ out, verify.CellBatchVerifier.pairing_holds_loop0 iter acc (frEncode r) (frEncode power) =
      ok out ∧ out.val = acc.val ++
        (computePowersAux r power (iter.end.val - iter.start.val)).map frEncode :=
  LeanBlsSimd.Kzg.Refinement.powers_loop h.blst r power acc iter hi hb

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

theorem weights_loop [e : KzgExternals] (h : ExternalsCorrect e)
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
        blst_ops.fr_add, h.blst.fr_add, hmut, acc']
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

theorem shifts_loop [e : KzgExternals] (h : ExternalsCorrect e)
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
        blst_ops.fr_mul, h.blst.fr_mul, ← hx, hpush, i]
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

theorem interpolation_frame [KzgExternals]
    (v next : verify.CellBatchVerifier) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize)) (point : blst.blst_p1)
    (hrun : verify.CellBatchVerifier.interpolation_commitment v indices cells = ok (point, next)) :
    next.r_powers = v.r_powers ∧ next.proof_points = v.proof_points := by
  unfold verify.CellBatchVerifier.interpolation_commitment at hrun
  obtain ⟨zero, _, hrun⟩ := bind_ok_exists _ _ _ hrun
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

private theorem resize_fields (v : alloc.vec.Vec blst.blst_fr) (n : Usize) (x : blst.blst_fr) :
    ∃ out, alloc.vec.Vec.resize blst.blst_fr.Insts.CoreCloneClone v n x = ok out ∧
      out.val = v.val.resize n.val x := by
  apply WP.spec_imp_exists
  apply alloc.vec.Vec.resize_spec
  simp [blst.blst_fr.Insts.CoreCloneClone.clone]

def InterpolationCorrect [KzgExternals] : Prop :=
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

theorem pairing_holds_composition [e : KzgExternals] (h : ExternalsCorrect e)
    (hinterp : InterpolationCorrect)
    (v : verify.CellBatchVerifier) (hv : StateInvariant v) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (commitments proofs : _root_.Array G1) (evals : _root_.Array CosetEvals) (r : Fr)
    (hb : indices.val.length * 2048 ≤ Isize.max.toNat)
    (hs : Model.RliInputs (indices.val.map (·.val)).toArray evals
      (computePowers r indices.val.length))
    (hc : v.commitment_points.val = commitments.toList.map g1Affine)
    (hp : v.proof_points.val = proofs.toList.map g1Affine)
    (hcell : InterpolationKernel.CellsRep cells evals)
    (he : v.kernel = none → v.evaluations.val = (evals.toList.flatMap _root_.Array.toList).map frEncode)
    (hunique : v.commitments.unique.val.length = commitments.size)
    (hci : v.commitments.index_of_cell.val.length = indices.val.length ∧
      ∀ i ∈ v.commitments.index_of_cell.val, i.val < commitments.size)
    (hproofs : proofs.size = indices.val.length)
    (hvalid : (∀ p ∈ commitments, G1Valid p) ∧ (∀ p ∈ proofs, G1Valid p)) :
    ∃ next, verify.CellBatchVerifier.pairing_holds v (frEncode r) indices cells =
      ok (Bls.pairingCheck (Model.pairingInputs embeddedSetup commitments proofs
        (v.commitments.index_of_cell.val.map (·.val)).toArray
        (indices.val.map (·.val)).toArray evals r), next) ∧ StateInvariant next := by
  let powers := computePowers r indices.val.length
  let weights := (List.range indices.val.length).foldl
    (weightStep v.commitments.index_of_cell.val powers.toList) (List.replicate commitments.size Fr.zero)
  let shifted := (List.range indices.val.length).map (shiftedScalar indices.val powers.toList)
  let interpolation := G1.msm (rustG1Bytes.map (fun b => (specPoint b).getD G1.zero))
    (Model.columnRli (indices.val.map (·.val)).toArray evals powers)
  have hplen : powers.size = indices.val.length := size_computePowers _ _
  have hwlen : weights.length = commitments.size := by simp [weights, weights_length]
  have hslen : shifted.length = indices.val.length := by simp [shifted]
  have hzero : blst_ops.fr_from_u64 0#u64 = ok (frEncode Fr.zero) := h.blst.fr_u64 0#u64
  have hone : blst_ops.fr_from_u64 1#u64 = ok (frEncode Fr.one) := h.blst.fr_u64 1#u64
  obtain ⟨powers0, hpowers0, hpowers0v⟩ := resize_fields v.r_powers 0#usize (frEncode Fr.zero)
  have hpowers0e : powers0.val = [] := by simpa [List.resize] using hpowers0v
  obtain ⟨powersV, hpowers, hpowersv⟩ := powers_loop h r Fr.one powers0
    { start := 0#usize, «end» := Slice.len indices } (by simp)
    (by simpa only [hpowers0e, List.length_nil, UScalar.ofNatCore_val_eq,
      Nat.sub_zero, Nat.zero_add] using indices.property)
  have hpowersE : powersV.val = powers.toList.map frEncode := by
    simpa only [hpowers0e, List.nil_append, UScalar.ofNatCore_val_eq, Nat.sub_zero,
      powers, computePowers, List.toList_toArray] using hpowersv
  obtain ⟨ll, scratchL, hll, hllrep⟩ := verify_lincomb_refinement h v.proof_points powersV
    proofs powers hp hpowersE (by omega) hvalid.2 v.lincomb
  obtain ⟨weights0, hweights0, hweights0v⟩ := resize_fields v.scalars 0#usize (frEncode Fr.zero)
  have hweights0e : weights0.val = [] := by simpa [List.resize] using hweights0v
  obtain ⟨weights0', hweights0', hweights0'v⟩ := resize_fields weights0
    (alloc.vec.Vec.len v.commitments.unique) (frEncode Fr.zero)
  have hweights0'e : weights0'.val = (List.replicate commitments.size Fr.zero).map frEncode := by
    simpa [hweights0e, List.resize, hunique] using hweights0'v
  obtain ⟨weightsV, hweights, hweightsv⟩ := weights_loop h v.commitments.index_of_cell
    powersV weights0' powers.toList (List.replicate commitments.size Fr.zero) hpowersE
    hweights0'e indices.val.length (by omega) (by simpa using hplen.ge)
    (by simpa using hci.2) { start := 0#usize, «end» := Slice.len indices } (by simp) (by simp)
  have hweightsE : weightsV.val = weights.map frEncode := by
    simpa only [UScalar.ofNatCore_val_eq, List.drop_zero, weights] using hweightsv
  obtain ⟨rlc, scratchC, hrlc, hrlcrep⟩ := verify_lincomb_refinement h v.commitment_points weightsV
    commitments weights.toArray hc (by simpa using hweightsE) (by simpa using hwlen.symm)
    hvalid.1 scratchL
  let middle := { v with r_powers := powersV, scalars := weightsV, lincomb := scratchC }
  obtain ⟨rli, after, hinterpolation, hafter, hrlirep⟩ :=
    hinterp middle hv indices cells evals powers hs hb hcell he hpowersE
  dsimp only [middle] at hinterpolation
  have hframe := interpolation_frame middle after indices cells rli hinterpolation
  have hafterPowers : after.r_powers.val = powers.toList.map frEncode := by
    rw [hframe.1]
    exact hpowersE
  have hafterProofs : after.proof_points.val = proofs.toList.map g1Affine := by
    rw [hframe.2]
    exact hp
  obtain ⟨shifted0, hshifted0, hshifted0v⟩ := resize_fields after.scalars 0#usize (frEncode Fr.zero)
  have hshifted0e : shifted0.val = [] := by simpa [List.resize] using hshifted0v
  have hindices : ∀ i ∈ indices.val, i.val < 128 := by
    intro i hi
    exact hs.2.2.1 i.val (by simp only [List.mem_toArray]; exact List.mem_map.mpr ⟨i, hi, rfl⟩)
  obtain ⟨shiftedV, hshifted, hshiftedv⟩ := shifts_loop h after.cosets hafter.2.1 after.r_powers
    shifted0 powers.toList hafterPowers indices (by simpa using hplen.ge) hindices
    { start := 0#usize, «end» := Slice.len indices } (by simp) (by simp)
    (by simpa only [hshifted0e, List.length_nil, UScalar.ofNatCore_val_eq,
      Nat.sub_zero, Nat.zero_add] using indices.property)
  have hshiftedE : shiftedV.val = shifted.map frEncode := by
    simpa only [hshifted0e, List.nil_append, UScalar.ofNatCore_val_eq, List.drop_zero,
      shifted] using hshiftedv
  obtain ⟨rlp, scratchP, hrlp, hrlprep⟩ := verify_lincomb_refinement h after.proof_points shiftedV
    proofs shifted.toArray hafterProofs (by simpa using hshiftedE) (by simp [hproofs, hslen])
    hvalid.2 after.lincomb
  have hvll := g1_msm_valid_of_mem proofs powers hvalid.2
  have hvrlc := g1_msm_valid_of_mem commitments weights.toArray hvalid.1
  have hvrli : G1Valid interpolation := g1_msm_valid_of_mem _ _ setup_model_points_valid
  have hvrlp := g1_msm_valid_of_mem proofs shifted.toArray hvalid.2
  obtain ⟨nrli, hneg, hnegrep⟩ := g1_neg_refinement h rli interpolation hrlirep hvrli
  obtain ⟨first, hfirst, hfirstrep⟩ := g1_add_refinement h rlc nrli _ _ hrlcrep hnegrep
    hvrlc (g1Valid_neg hvrli)
  obtain ⟨right, hright, hrightrep⟩ := g1_add_refinement h first rlp _ _ hfirstrep hrlprep
    (g1Valid_add hvrlc (g1Valid_neg hvrli)) hvrlp
  have hpair := pairing_call_refinement h after.setup hafter.1 ll right _ _ hllrep hrightrep
    hvll (g1Valid_add (g1Valid_add hvrlc (g1Valid_neg hvrli)) hvrlp)
  have hwmodel := weights_model v.commitments.index_of_cell.val powers commitments.size
  rw [hci.1] at hwmodel
  have hsmodel := shifted_model indices.val powers hplen.ge
  have hmodel : Model.pairingInputs embeddedSetup commitments proofs
      (v.commitments.index_of_cell.val.map (·.val)).toArray
      (indices.val.map (·.val)).toArray evals r =
      #[(G1.msm proofs powers, embeddedSetup.g2Monomial[64]!),
        (G1.add (G1.add (G1.msm commitments weights.toArray) (G1.neg interpolation))
          (G1.msm proofs shifted.toArray), G2.neg embeddedSetup.g2Monomial[0]!)] := by
    unfold Model.pairingInputs
    simp only [List.size_toArray, List.length_map]
    rw [← setup_model_points_eq, ← hwmodel, ← hsmodel]
  let next := { after with scalars := shiftedV, lincomb := scratchP }
  have hfinish := congrArg (fun result : Result Bool => do let b ← result; ok (b, next)) hpair
  simp only [bind_tc_ok, bind_assoc_eq] at hfinish
  refine ⟨next, ?_, hafter⟩
  rw [hmodel]
  unfold verify.CellBatchVerifier.pairing_holds
  simp only [hzero, hpowers0, hone, hpowers, hll, hweights0, hweights0', hweights,
    hrlc, hinterpolation, hshifted0, hshifted, hrlp, hneg, hfirst, hright,
    bind_tc_ok, Function.uncurry_apply_pair]
  exact hfinish

end LeanBlsSimd.Kzg.Pairing

namespace LeanBlsSimd.Kzg

theorem pairing_holds_refinement [e : KzgExternals] (h : ExternalsCorrect e)
    (v : verify.CellBatchVerifier) (hv : StateInvariant v) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (commitments proofs : _root_.Array G1) (evals : _root_.Array CosetEvals) (r : Fr)
    (hb : indices.val.length * 2048 ≤ Isize.max.toNat)
    (hs : Model.RliInputs (indices.val.map (·.val)).toArray evals
      (computePowers r indices.val.length))
    (hc : v.commitment_points.val = commitments.toList.map g1Affine)
    (hp : v.proof_points.val = proofs.toList.map g1Affine)
    (hcell : InterpolationKernel.CellsRep cells evals)
    (he : v.kernel = none → v.evaluations.val = (evals.toList.flatMap _root_.Array.toList).map frEncode)
    (hunique : v.commitments.unique.val.length = commitments.size)
    (hci : v.commitments.index_of_cell.val.length = indices.val.length ∧
      ∀ i ∈ v.commitments.index_of_cell.val, i.val < commitments.size)
    (hproofs : proofs.size = indices.val.length)
    (hvalid : (∀ p ∈ commitments, G1Valid p) ∧ (∀ p ∈ proofs, G1Valid p)) :
    ∃ next, verify.CellBatchVerifier.pairing_holds v (frEncode r) indices cells =
      ok (Bls.pairingCheck (Model.pairingInputs embeddedSetup commitments proofs
        (v.commitments.index_of_cell.val.map (·.val)).toArray
        (indices.val.map (·.val)).toArray evals r), next) ∧ StateInvariant next :=
  Pairing.pairing_holds_composition h (interpolation_commitment_refinement h)
    v hv indices cells commitments proofs evals r hb hs hc hp hcell he hunique hci hproofs hvalid

end LeanBlsSimd.Kzg
