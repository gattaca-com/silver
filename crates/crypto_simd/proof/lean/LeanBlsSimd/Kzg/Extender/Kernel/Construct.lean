import LeanBlsSimd.Kzg.Extender.Kernel.Fft

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel

set_option maxRecDepth 8000

private def Factors (factors : Array blst.blst_fr 8#usize) (v count : Nat) : Prop :=
  ∀ lane : Fin 8, lane.val < count →
    factors.val[lane.val]! = frEncode (shiftFactor (8 * v + lane.val) * Fr.ofNat 16)

private theorem factors_loop (hfr : FrCorrect)
    (shifts : Slice blst.blst_fr) (hsize : shifts.val.length = 4096)
    (hlookup : ∀ i, i < 4096 → shifts.val[i]! = frEncode (Kzg.Model.roots 13)[i]!)
    (v : Usize) (hv : v.val < 512) (factors : Array blst.blst_fr 8#usize)
    (lane : Usize) (hl : lane.val ≤ 8) (hf : Factors factors v.val lane.val) :
    ∃ out, extension_kernel.ExtensionKernel.new_loop0_loop0 shifts
      (frEncode (Fr.ofNat 4096).inverse) factors v lane = ok out ∧ Factors out v.val 8 := by
  induction hrem : 8 - lane.val generalizing lane factors with
  | zero =>
    have he : lane.val = 8 := by omega
    refine ⟨factors, ?_, by simpa only [he] using hf⟩
    rw [extension_kernel.ExtensionKernel.new_loop0_loop0, loop.eq_1]
    simp [extension_kernel.ExtensionKernel.new_loop0_loop0.body, fr8.LANES,
      UScalar.lt_equiv, he]
  | succ rem ih =>
    have hlt : lane.val < 8 := by omega
    let base : Usize := UScalar.ofNatCore (v.val * 8) (by scalar_tac)
    let index : Usize := UScalar.ofNatCore (v.val * 8 + lane.val) (by scalar_tac)
    let lane' : Usize := UScalar.ofNatCore (lane.val + 1) (by scalar_tac)
    have hb : base.val = v.val * 8 := UScalar.ofNatCore_val_eq _
    have hi : index.val = v.val * 8 + lane.val := UScalar.ofNatCore_val_eq _
    have hl' : lane'.val = lane.val + 1 := UScalar.ofNatCore_val_eq _
    have hmul : v * 8#usize = ok base := scalar_mul_ok v 8#usize (by scalar_tac)
    have hadd : base + lane = ok index := scalar_add_ok base lane (by scalar_tac)
    have hinc : lane + 1#usize = ok lane' := scalar_add_ok lane 1#usize (by scalar_tac)
    have hindex : Slice.index_usize shifts index =
        ok (frEncode (Kzg.Model.roots 13)[8 * v.val + lane.val]!) := by
      have hib : index.val < shifts.val.length := by rw [hi, hsize]; omega
      simp only [Slice.index_usize, Slice.getElem?_Usize_eq, List.getElem?_eq_getElem hib]
      rw [← getElem!_pos shifts.val index.val hib, hi, Nat.mul_comm v.val 8,
        hlookup _ (by omega)]
    have hproduct : fr.fr_mul
        (frEncode (Kzg.Model.roots 13)[8 * v.val + lane.val]!)
        (frEncode (Fr.ofNat 4096).inverse) =
        ok (frEncode (shiftFactor (8 * v.val + lane.val))) :=
      hfr.fr_mul _ _
    have hmultiplier := (multiplier_refinement hfr (shiftFactor (8 * v.val + lane.val))).1
    let next := Aeneas.Std.Array.set factors lane (frEncode (shiftFactor (8 * v.val + lane.val) * Fr.ofNat 16))
    have hupdate : Array.update factors lane
        (frEncode (shiftFactor (8 * v.val + lane.val) * Fr.ofNat 16)) = ok next := by
      have hb : lane.val < factors.val.length := by simpa only [factors.property] using hlt
      simp [Array.update, List.getElem?_eq_getElem hb, next, Aeneas.Std.Array.set]
    have hprefix : Factors next v.val lane'.val := by
      intro j hj
      by_cases he : j.val = lane.val
      · rw [he]
        simp [next, Aeneas.Std.Array.set, factors.property, hlt]
      · rw [show next.val = factors.val.set lane.val
          (frEncode (shiftFactor (8 * v.val + lane.val) * Fr.ofNat 16)) from rfl,
          List.getElem!_set_ne _ _ _ _ (by omega)]
        exact hf j (by omega)
    obtain ⟨out, hout, ho⟩ := ih next lane' (by omega) hprefix (by omega)
    refine ⟨out, ?_, ho⟩
    have hbody : extension_kernel.ExtensionKernel.new_loop0_loop0.body shifts
        (frEncode (Fr.ofNat 4096).inverse) v factors lane = ok (cont (next, lane')) := by
      simp only [extension_kernel.ExtensionKernel.new_loop0_loop0.body, fr8.LANES,
        UScalar.lt_equiv, UScalar.ofNatCore_val_eq, hlt, if_true, hmul, hadd, hindex,
        hproduct, hmultiplier, hupdate, hinc, bind_tc_ok]
    rw [extension_kernel.ExtensionKernel.new_loop0_loop0, loop.eq_1]
    simpa only [hbody] using hout

private def ConstructorPrefix (shift data : alloc.vec.Vec fr8.Fr8) (count : Nat) : Prop :=
  shift.val.length = count ∧ data.val.length = count ∧
    (∀ v : Fin count, MultiplierRep shift.val[v.val]!
      (fun lane => shiftFactor (8 * v.val + lane.val))) ∧
    ∀ v : Fin count, Represents data.val[v.val]! (fun _ => 0)

private theorem vector_count : 4096#usize / fr8.LANES = ok 512#usize := by
  obtain ⟨out, hout, hv⟩ := UScalar.div_spec 4096#usize (y := fr8.LANES) (by simp [fr8.LANES])
  have he : out = 512#usize := by
    apply UScalar.eq_of_val_eq
    simpa only [fr8.LANES, UScalar.ofNatCore_val_eq] using hv
  simpa only [he] using hout

private theorem constructor_loop (hfr : FrCorrect)
    (shifts : Slice blst.blst_fr) (hsize : shifts.val.length = 4096)
    (hlookup : ∀ i, i < 4096 → shifts.val[i]! = frEncode (Kzg.Model.roots 13)[i]!)
    (shift data : alloc.vec.Vec fr8.Fr8) (factors : Array blst.blst_fr 8#usize)
    (v : Usize) (hv : v.val ≤ 512) (hp : ConstructorPrefix shift data v.val) :
    ∃ finalShift finalData, extension_kernel.ExtensionKernel.new_loop0 shifts
      (frEncode (Fr.ofNat 4096).inverse) 4096#usize shift data factors v =
        ok (finalShift, finalData) ∧ ConstructorPrefix finalShift finalData 512 := by
  induction hrem : 512 - v.val generalizing shift data factors v with
  | zero =>
    have he : v.val = 512 := by omega
    refine ⟨shift, data, ?_, by simpa only [he] using hp⟩
    rw [extension_kernel.ExtensionKernel.new_loop0, loop.eq_1]
    have hdiv := vector_count
    simp [extension_kernel.ExtensionKernel.new_loop0.body, hdiv, UScalar.lt_equiv, he]
  | succ rem ih =>
    have hlt : v.val < 512 := by omega
    obtain ⟨factors', hfactors, hf⟩ := factors_loop hfr shifts hsize hlookup v hlt
      factors 0#usize (by decide) (by intro lane h; exact (Nat.not_lt_zero _ h).elim)
    obtain ⟨factor, hload, hfactor⟩ := load_multiplier_refinement
      (Array.to_slice factors') 0#usize (fun lane => shiftFactor (8 * v.val + lane.val))
      (by simp [Array.to_slice, factors'.property])
      (by intro lane; simpa only [Array.to_slice, UScalar.ofNatCore_val_eq, Nat.zero_add] using hf lane lane.isLt)
    obtain ⟨zero, hzero, hzeroRep⟩ := zero_refinement
    have hshiftBound : shift.val.length + 1 ≤ Usize.max := by rw [hp.1]; scalar_tac
    have hdataBound : data.val.length + 1 ≤ Usize.max := by rw [hp.2.1]; scalar_tac
    let shift' : alloc.vec.Vec fr8.Fr8 := ⟨shift.val ++ [factor], by simpa using hshiftBound⟩
    let data' : alloc.vec.Vec fr8.Fr8 := ⟨data.val ++ [zero], by simpa using hdataBound⟩
    let v' : Usize := UScalar.ofNatCore (v.val + 1) (by scalar_tac)
    have hv' : v'.val = v.val + 1 := UScalar.ofNatCore_val_eq _
    have hpushShift : alloc.vec.Vec.push shift factor = ok shift' := by
      simp [alloc.vec.Vec.push, hshiftBound, shift']
    have hpushData : alloc.vec.Vec.push data zero = ok data' := by
      simp [alloc.vec.Vec.push, hdataBound, data']
    have hinc : v + 1#usize = ok v' := scalar_add_ok v 1#usize (by scalar_tac)
    have hprefix : ConstructorPrefix shift' data' v'.val := by
      refine ⟨by simp [shift', hp.1, hv'], by simp [data', hp.2.1, hv'], ?_, ?_⟩
      · intro j
        by_cases hj : j.val < v.val
        · change MultiplierRep (shift.val ++ [factor])[j.val]! _
          rw [List.getElem!_append_left _ _ _ (by rw [hp.1]; exact hj)]
          exact hp.2.2.1 ⟨j.val, hj⟩
        · have he : j.val = v.val := by omega
          change MultiplierRep (shift.val ++ [factor])[j.val]! _
          rw [List.getElem!_append_right _ _ _ (by rw [hp.1, he])]
          simpa only [hp.1, he, Nat.sub_self, List.getElem!_cons_zero] using hfactor
      · intro j
        by_cases hj : j.val < v.val
        · change Represents (data.val ++ [zero])[j.val]! _
          rw [List.getElem!_append_left _ _ _ (by rw [hp.2.1]; exact hj)]
          exact hp.2.2.2 ⟨j.val, hj⟩
        · have he : j.val = v.val := by omega
          change Represents (data.val ++ [zero])[j.val]! _
          rw [List.getElem!_append_right _ _ _ (by rw [hp.2.1, he])]
          simpa only [hp.2.1, he, Nat.sub_self, List.getElem!_cons_zero] using hzeroRep
    obtain ⟨finalShift, finalData, hout, ho⟩ := ih shift' data' factors' v'
      (by omega) hprefix (by omega)
    refine ⟨finalShift, finalData, ?_, ho⟩
    have hdiv := vector_count
    have hbody : extension_kernel.ExtensionKernel.new_loop0.body shifts
        (frEncode (Fr.ofNat 4096).inverse) 4096#usize shift data factors v =
        ok (cont (shift', data', factors', v')) := by
      simp only [extension_kernel.ExtensionKernel.new_loop0.body, hdiv, bind_tc_ok,
        UScalar.lt_equiv, UScalar.ofNatCore_val_eq, hlt, if_true, hfactors, lift,
        hload, hpushShift, hzero, hpushData, hinc]
    rw [extension_kernel.ExtensionKernel.new_loop0, loop.eq_1]
    simpa only [hbody] using hout

private theorem sample_blob (roots : _root_.Array Fr) (hsize : roots.size = 4096) :
    sampleRoots roots 4096 = roots := by
  apply _root_.Array.ext
  · simpa only [sampleRoots, _root_.Array.size_ofFn] using hsize.symm
  · intro i hi hj
    simp only [sampleRoots, _root_.Array.getElem_ofFn, hsize, Nat.div_self (by decide : 0 < 4096),
      Nat.mul_one, getElem!_pos roots i hj]

theorem new_refinement (hfr : FrCorrect)
    (roots inverseRoots shifts : Slice blst.blst_fr) (inverseSize : blst.blst_fr)
    (hroots : roots.val = (Kzg.Model.roots 12).toList.map frEncode)
    (hinverse : inverseRoots.val =
      (Kzg.Model.inverseRoots (Kzg.Model.roots 12)).toList.map frEncode)
    (hshifts : shifts.val = ((Kzg.Model.roots 13).extract 0 4096).toList.map frEncode)
    (hscale : inverseSize = frEncode (Fr.ofNat 4096).inverse) :
    ∃ initial, extension_kernel.ExtensionKernel.new roots inverseRoots shifts inverseSize = ok initial ∧
      StateInvariant initial ∧
      DataRep (alloc.vec.Vec.deref initial.data) (_root_.Array.replicate 4096 (0 : Fr)) := by
  subst inverseSize
  have hlen : shifts.val.length = 4096 := by simp [hshifts, Kzg.Model.roots]
  have hlookup (i : Nat) (hi : i < 4096) : shifts.val[i]! = frEncode (Kzg.Model.roots 13)[i]! := by
    rw [hshifts, getElem!_pos _ i (by simp [Kzg.Model.roots]; omega)]
    simp only [List.getElem_map, _root_.Array.getElem_toList, _root_.Array.getElem_extract,
      Nat.zero_add]
    rw [getElem!_pos (Kzg.Model.roots 13) i (by simp [Kzg.Model.roots]; omega)]
  let empty := alloc.vec.Vec.with_capacity fr8.Fr8 512#usize
  let factors := Array.repeat 8#usize (frEncode 0)
  have hempty : ConstructorPrefix empty empty 0 := by
    refine ⟨rfl, rfl, ?_, ?_⟩ <;> intro j <;> exact j.elim0
  obtain ⟨shift, data, hconstruct, hp⟩ := constructor_loop hfr shifts hlen hlookup
    empty empty factors 0#usize (by decide) hempty
  have hn : TransformSize (4096#usize).val := ⟨12, by decide, by decide, by decide⟩
  have hrs : (Kzg.Model.roots 12).size = 4096 := by simp [Kzg.Model.roots]
  have his : (Kzg.Model.inverseRoots (Kzg.Model.roots 12)).size = 4096 := by
    simp [Kzg.Model.inverseRoots, Kzg.Model.roots]
  obtain ⟨inverse, hiNew, hiInv⟩ := fft_new_refinement hfr inverseRoots
    (Kzg.Model.inverseRoots (Kzg.Model.roots 12)) 4096#usize hn
    (by omega) (by simp only [his, UScalar.ofNatCore_val_eq]) hinverse
  obtain ⟨forward, hfNew, hfInv⟩ := fft_new_refinement hfr roots
    (Kzg.Model.roots 12) 4096#usize hn
    (by omega) (by simp only [hrs, UScalar.ofNatCore_val_eq]) hroots
  rw [show (4096#usize).val = 4096 from rfl, sample_blob _ his] at hiInv
  rw [show (4096#usize).val = 4096 from rfl, sample_blob _ hrs] at hfInv
  let initial : extension_kernel.ExtensionKernel := ⟨inverse, forward, shift, data⟩
  refine ⟨initial, ?_, ⟨hiInv, hfInv, hp.1, hp.2.1, hp.2.2.1⟩, ?_⟩
  · have hlength : Slice.len shifts = 4096#usize := by
      apply UScalar.eq_of_val_eq
      simpa only [Slice.len, UScalar.ofNatCore_val_eq] using hlen
    dsimp only [empty, factors] at hconstruct
    simp only [extension_kernel.ExtensionKernel.new, hlength, vector_count, bind_tc_ok,
      fr_zero_eq,
      show Fr.ofNat 0 = 0 from rfl, hconstruct, hiNew, hfNew,
      Function.uncurry_apply_pair, initial]
  · refine ⟨by simp [initial, alloc.vec.Vec.deref, hp.2.1], ?_⟩
    intro v
    have hv : v.val < 512 := by simpa only [initial, alloc.vec.Vec.deref, hp.2.1] using v.isLt
    have hi (lane : Fin 8) : 8 * v.val + lane.val < 4096 := by omega
    have hr := hp.2.2.2 ⟨v.val, hv⟩
    rw [getElem!_pos data.val v.val v.isLt] at hr
    refine ⟨hr.1, fun lane => ?_⟩
    simp only [initial, alloc.vec.Vec.deref]
    simpa only [_root_.Array.getElem!_replicate, hi, if_true] using hr.2 lane

end LeanBlsSimd.Kzg.Extender.Kernel
