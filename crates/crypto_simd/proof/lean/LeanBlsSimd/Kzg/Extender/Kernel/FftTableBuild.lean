import LeanBlsSimd.Kzg.Extender.Kernel.Fr8
import LeanBlsSimd.Kzg.Extender.Decode

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open scoped EthLib.Cryptography.Bls.Fr
open silver_crypto_simd silver_crypto_simd.kzg

attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero

namespace LeanBlsSimd.Kzg.Extender.Kernel

private def TwiddlePrefix (twiddles : Array blst.blst_fr 8#usize)
    (values : Fin 8 → Fr) (count : Nat) : Prop :=
  ∀ lane : Fin 8, lane.val < count → twiddles.val[lane.val]! = frEncode (values lane * Fr.ofNat 16)

private theorem twiddle_loop
    (input : Slice blst.blst_fr) (roots : _root_.Array Fr)
    (hinput : input.val = roots.toList.map frEncode)
    (step start h : Usize) (hstep : 0 < step.val) (hh : 0 < h.val)
    (hbound : ∀ lane : Fin 8, (start.val + lane.val % h.val) * step.val < roots.size)
    (twiddles : Array blst.blst_fr 8#usize) (m : Usize) (hm : m.val ≤ 8)
    (hp : TwiddlePrefix twiddles
      (fun lane => roots[(start.val + lane.val % h.val) * step.val]!) m.val) :
    ∃ out, fft8.stage_twiddles_loop input step start h twiddles m = ok out ∧
      TwiddlePrefix out (fun lane => roots[(start.val + lane.val % h.val) * step.val]!) 8 := by
  have hlen : input.val.length = roots.size := by simp only [hinput, List.length_map, _root_.Array.length_toList]
  have hmax : roots.size ≤ Usize.max := hlen ▸ input.property
  induction hrem : 8 - m.val generalizing twiddles m with
  | zero =>
    have he : m.val = 8 := by omega
    refine ⟨twiddles, ?_, by simpa only [he] using hp⟩
    rw [fft8.stage_twiddles_loop, loop.eq_1]
    simp [fft8.stage_twiddles_loop.body, fr8.LANES, UScalar.lt_equiv, he]
  | succ rem ih =>
    have hml : m.val < 8 := by omega
    obtain ⟨modulo, hmod, hmval⟩ := WP.spec_imp_exists (UScalar.rem_spec m (y := h) (by omega))
    have hindexBound := hbound ⟨m.val, hml⟩
    have hsumBound : start.val + modulo.val < 2 ^ UScalarTy.Usize.numBits := by
      have hs : start.val + modulo.val ≤ (start.val + modulo.val) * step.val := Nat.le_mul_of_pos_right _ hstep
      rw [hmval] at hs
      scalar_tac
    let sum : Usize := UScalar.ofNatCore (start.val + modulo.val) hsumBound
    have hsval : sum.val = start.val + modulo.val := UScalar.ofNatCore_val_eq _
    have hproductBound : sum.val * step.val < 2 ^ UScalarTy.Usize.numBits := by
      rw [hsval, hmval]
      scalar_tac
    let index : Usize := UScalar.ofNatCore (sum.val * step.val) hproductBound
    let m' : Usize := UScalar.ofNatCore (m.val + 1) (by scalar_tac)
    have hival : index.val = (start.val + m.val % h.val) * step.val := by
      simp only [index, UScalar.ofNatCore_val_eq, hsval, hmval]
    have hm' : m'.val = m.val + 1 := UScalar.ofNatCore_val_eq _
    have hadd : start + modulo = ok sum := scalar_add_ok start modulo hsumBound
    have hmul : sum * step = ok index := scalar_mul_ok sum step hproductBound
    have hinc : m + 1#usize = ok m' := scalar_add_ok m 1#usize (by scalar_tac)
    have hlookup : Slice.index_usize input index = ok (frEncode roots[index.val]!) := by
      have hib : index.val < input.val.length := by rw [hlen, hival]; exact hindexBound
      simp only [Slice.index_usize, Slice.getElem?_Usize_eq, List.getElem?_eq_getElem hib]
      simp only [hinput, List.getElem_map, _root_.Array.getElem_toList]
      rw [getElem!_pos roots index.val (by omega)]
    have hmultiplier := (multiplier_refinement roots[index.val]!).1
    let value := frEncode (roots[index.val]! * Fr.ofNat 16)
    let next := Aeneas.Std.Array.set twiddles m value
    have hupdate : Array.update twiddles m value = ok next := by
      have hb : m.val < twiddles.val.length := by simpa only [twiddles.property] using hml
      simp [Array.update, List.getElem?_eq_getElem hb, next, Aeneas.Std.Array.set]
    have hprefix : TwiddlePrefix next
        (fun lane => roots[(start.val + lane.val % h.val) * step.val]!) m'.val := by
      intro lane hlane
      by_cases he : lane.val = m.val
      · rw [he]
        simp [next, Aeneas.Std.Array.set, twiddles.property, hml, value, hival, he]
      · rw [show next.val = twiddles.val.set m.val value from rfl,
          List.getElem!_set_ne _ _ _ _ (by omega)]
        exact hp lane (by omega)
    obtain ⟨out, hout, ho⟩ := ih next m' (by omega) hprefix (by omega)
    refine ⟨out, ?_, ho⟩
    have hbody : fft8.stage_twiddles_loop.body input step start h twiddles m =
        ok (cont (next, m')) := by
      simp only [fft8.stage_twiddles_loop.body, fr8.LANES, UScalar.lt_equiv,
        UScalar.ofNatCore_val_eq, hml, if_true, hmod, hadd, hmul, hlookup,
        hmultiplier, hupdate, hinc, bind_tc_ok, value]
    rw [fft8.stage_twiddles_loop, loop.eq_1]
    simpa only [hbody] using hout

theorem stage_twiddles_refinement
    (input : Slice blst.blst_fr) (roots : _root_.Array Fr)
    (hinput : input.val = roots.toList.map frEncode)
    (step start h : Usize) (hstep : 0 < step.val) (hh : 0 < h.val)
    (hbound : ∀ lane : Fin 8, (start.val + lane.val % h.val) * step.val < roots.size) :
    ∃ out, fft8.stage_twiddles input step start h = ok out ∧
      ∀ lane : Fin 8, out.val[lane.val]! =
        frEncode (roots[(start.val + lane.val % h.val) * step.val]! * Fr.ofNat 16) := by
  obtain ⟨out, hout, ho⟩ := twiddle_loop input roots hinput step start h hstep hh hbound
    (Array.repeat 8#usize (frEncode 0)) 0#usize (by decide)
    (by intro lane hlane; exact (Nat.not_lt_zero _ hlane).elim)
  refine ⟨out, ?_, fun lane => ho lane lane.isLt⟩
  simpa only [fft8.stage_twiddles, fr_zero_eq,
    UScalar.ofNatCore_val_eq, show Fr.ofNat 0 = 0 from rfl, bind_tc_ok] using hout

private def WideStagePrefix (wide : alloc.vec.Vec fr8.Fr8) (roots : _root_.Array Fr)
    (half count : Nat) : Prop :=
  wide.val.length = half / 8 - 1 + count ∧
    ∀ v : Fin count, MultiplierRep wide.val[half / 8 - 1 + v.val]!
      (fun lane => roots[(8 * v.val + lane.val) * (roots.size / (2 * half))]!)

private theorem wide_stage_loop
    (input : Slice blst.blst_fr) (roots : _root_.Array Fr)
    (hinput : input.val = roots.toList.map frEncode) (n stride half : Usize)
    (hproduct : stride.val * n.val = roots.size)
    (hhalf : 8 ≤ half.val) (hhalfN : 2 * half.val ≤ n.val)
    (hn : n.val ≤ 4096) (hrootN : n.val ≤ roots.size)
    (wide : alloc.vec.Vec fr8.Fr8) (v : Usize) (hv : v.val ≤ half.val / 8)
    (hp : WideStagePrefix wide roots half.val v.val) :
    ∃ out, fft8.Fft8.new_loop1_loop0 input n stride wide half v = ok out ∧
      WideStagePrefix out roots half.val (half.val / 8) ∧
      ∀ i, i < half.val / 8 - 1 → out.val[i]! = wide.val[i]! := by
  have hlen : input.val.length = roots.size := by simp only [hinput, List.length_map, _root_.Array.length_toList]
  have hmax : roots.size ≤ Usize.max := hlen ▸ input.property
  obtain ⟨count, hcount, hcval⟩ := UScalar.div_spec half (y := fr8.LANES) (by simp [fr8.LANES])
  simp only [fr8.LANES, UScalar.ofNatCore_val_eq] at hcval
  induction hrem : half.val / 8 - v.val generalizing wide v with
  | zero =>
    have he : v.val = half.val / 8 := by omega
    refine ⟨wide, ?_, by simpa only [he] using hp, fun _ _ => rfl⟩
    rw [fft8.Fft8.new_loop1_loop0, loop.eq_1]
    simp [fft8.Fft8.new_loop1_loop0.body, hcount, UScalar.lt_equiv, hcval, he]
  | succ rem ih =>
    have hvt : v.val < half.val / 8 := by omega
    let total : Usize := UScalar.ofNatCore (stride.val * n.val) (by rw [hproduct]; scalar_tac)
    let twice : Usize := UScalar.ofNatCore (2 * half.val) (by scalar_tac)
    let start : Usize := UScalar.ofNatCore (v.val * 8) (by scalar_tac)
    let v' : Usize := UScalar.ofNatCore (v.val + 1) (by scalar_tac)
    have htval : total.val = roots.size := by simp only [total, UScalar.ofNatCore_val_eq, hproduct]
    have htwoval : twice.val = 2 * half.val := UScalar.ofNatCore_val_eq _
    have hsval : start.val = v.val * 8 := UScalar.ofNatCore_val_eq _
    have hv' : v'.val = v.val + 1 := UScalar.ofNatCore_val_eq _
    have htotal : stride * n = ok total := scalar_mul_ok stride n (by rw [hproduct]; scalar_tac)
    have htwice : 2#usize * half = ok twice := scalar_mul_ok 2#usize half (by scalar_tac)
    have hstart : v * fr8.LANES = ok start := by
      simpa only [fr8.LANES] using scalar_mul_ok v 8#usize (by scalar_tac)
    have hinc : v + 1#usize = ok v' := scalar_add_ok v 1#usize (by scalar_tac)
    obtain ⟨step, hdiv, hstepval⟩ := UScalar.div_spec total (y := twice) (by omega)
    rw [htval, htwoval] at hstepval
    have hstep : 0 < step.val := by
      rw [hstepval]
      exact Nat.div_pos (by omega) (by omega)
    have hbound (lane : Fin 8) : (start.val + lane.val % half.val) * step.val < roots.size := by
      have hmod : lane.val % half.val = lane.val := Nat.mod_eq_of_lt (by omega)
      rw [hsval, hmod, hstepval]
      have hsmall : v.val * 8 + lane.val < 2 * half.val := by omega
      have hle := Nat.div_mul_le_self roots.size (2 * half.val)
      have hlt := Nat.mul_lt_mul_of_pos_right hsmall hstep
      rw [hstepval] at hlt
      exact lt_of_lt_of_le hlt (by simpa only [Nat.mul_comm] using hle)
    obtain ⟨twiddles, htwiddles, htw⟩ := stage_twiddles_refinement input roots hinput
      step start half hstep (by omega) hbound
    obtain ⟨factor, hload, hfactor⟩ := load_multiplier_refinement
      (Array.to_slice twiddles) 0#usize
      (fun lane => roots[(8 * v.val + lane.val) * (roots.size / (2 * half.val))]!)
      (by simp [Array.to_slice, twiddles.property]) (by
        intro lane
        have hmod : lane.val % half.val = lane.val := Nat.mod_eq_of_lt (by omega)
        simpa only [Array.to_slice, UScalar.ofNatCore_val_eq, Nat.zero_add,
          hsval, hstepval, hmod, Nat.mul_comm v.val 8] using htw lane)
    have hpushBound : wide.val.length + 1 ≤ Usize.max := by rw [hp.1]; scalar_tac
    let next : alloc.vec.Vec fr8.Fr8 := ⟨wide.val ++ [factor], by simpa using hpushBound⟩
    have hpush : alloc.vec.Vec.push wide factor = ok next := by
      simp [alloc.vec.Vec.push, hpushBound, next]
    have hprefix : WideStagePrefix next roots half.val v'.val := by
      refine ⟨by simp [next, hp.1, hv', Nat.add_assoc], ?_⟩
      intro j
      by_cases hj : j.val < v.val
      · change MultiplierRep (wide.val ++ [factor])[half.val / 8 - 1 + j.val]! _
        rw [List.getElem!_append_left _ _ _ (by rw [hp.1]; omega)]
        exact hp.2 ⟨j.val, hj⟩
      · have he : j.val = v.val := by omega
        change MultiplierRep (wide.val ++ [factor])[half.val / 8 - 1 + j.val]! _
        rw [List.getElem!_append_right _ _ _ (by rw [hp.1, he])]
        simpa only [hp.1, he, Nat.sub_self, List.getElem!_cons_zero] using hfactor
    obtain ⟨out, hout, ho, hframe⟩ := ih next v' (by omega) hprefix (by omega)
    refine ⟨out, ?_, ho, ?_⟩
    · have hbody : fft8.Fft8.new_loop1_loop0.body input n stride half wide v = ok (cont (next, v')) := by
        simp only [fft8.Fft8.new_loop1_loop0.body, hcount, bind_tc_ok,
          UScalar.lt_equiv, hcval, hvt, if_true, htotal, htwice, hdiv,
          hstart, htwiddles, lift, hload, hpush, hinc]
      rw [fft8.Fft8.new_loop1_loop0, loop.eq_1]
      simpa only [hbody] using hout
    · intro i hi
      rw [hframe i hi]
      exact List.getElem!_append_left _ _ _ (by rw [hp.1]; omega)

theorem wide_stage_refinement
    (input : Slice blst.blst_fr) (roots : _root_.Array Fr)
    (hinput : input.val = roots.toList.map frEncode) (n stride half : Usize)
    (hproduct : stride.val * n.val = roots.size)
    (hhalf : 8 ≤ half.val) (hhalfN : 2 * half.val ≤ n.val)
    (hn : n.val ≤ 4096) (hrootN : n.val ≤ roots.size)
    (wide : alloc.vec.Vec fr8.Fr8) (hlen : wide.val.length = half.val / 8 - 1) :
    ∃ out, fft8.Fft8.new_loop1_loop0 input n stride wide half 0#usize = ok out ∧
      out.val.length = half.val / 8 - 1 + half.val / 8 ∧
      (∀ v : Fin (half.val / 8), MultiplierRep out.val[half.val / 8 - 1 + v.val]!
        (fun lane => roots[(8 * v.val + lane.val) * (roots.size / (2 * half.val))]!)) ∧
      ∀ i, i < half.val / 8 - 1 → out.val[i]! = wide.val[i]! := by
  obtain ⟨out, hout, hp, hframe⟩ := wide_stage_loop input roots hinput n stride half
    hproduct hhalf hhalfN hn hrootN wide 0#usize (by simp)
    ⟨by simpa using hlen, fun v => v.elim0⟩
  exact ⟨out, hout, hp.1, hp.2, hframe⟩

private def ShortStagePrefix (short : alloc.vec.Vec fr8.Fr8) (roots : _root_.Array Fr)
    (half count : Nat) : Prop :=
  short.val.length = half - 1 + count ∧
    ∀ v : Fin count, MultiplierRep short.val[half - 1 + v.val]!
      (fun _ => roots[v.val * (roots.size / (2 * half))]!)

private theorem short_stage_loop
    (input : Slice blst.blst_fr) (roots : _root_.Array Fr)
    (hinput : input.val = roots.toList.map frEncode) (n stride half : Usize)
    (hproduct : stride.val * n.val = roots.size)
    (hhalf : 0 < half.val) (hhalfMax : half.val ≤ 4) (hhalfN : 2 * half.val ≤ n.val)
    (hn : n.val ≤ 4096) (hrootN : n.val ≤ roots.size)
    (short : alloc.vec.Vec fr8.Fr8) (v : Usize) (hv : v.val ≤ half.val)
    (hp : ShortStagePrefix short roots half.val v.val) :
    ∃ out, fft8.Fft8.new_loop0_loop0 input n stride short half v = ok out ∧
      ShortStagePrefix out roots half.val (half.val) ∧
      ∀ i, i < half.val - 1 → out.val[i]! = short.val[i]! := by
  have hlen : input.val.length = roots.size := by simp only [hinput, List.length_map, _root_.Array.length_toList]
  have hmax : roots.size ≤ Usize.max := hlen ▸ input.property
  induction hrem : half.val - v.val generalizing short v with
  | zero =>
    have he : v.val = half.val := by omega
    refine ⟨short, ?_, by simpa only [he] using hp, fun _ _ => rfl⟩
    rw [fft8.Fft8.new_loop0_loop0, loop.eq_1]
    simp [fft8.Fft8.new_loop0_loop0.body, UScalar.lt_equiv, he]
  | succ rem ih =>
    have hvt : v.val < half.val := by omega
    let total : Usize := UScalar.ofNatCore (stride.val * n.val) (by rw [hproduct]; scalar_tac)
    let twice : Usize := UScalar.ofNatCore (2 * half.val) (by scalar_tac)
    let v' : Usize := UScalar.ofNatCore (v.val + 1) (by scalar_tac)
    have htval : total.val = roots.size := by simp only [total, UScalar.ofNatCore_val_eq, hproduct]
    have htwoval : twice.val = 2 * half.val := UScalar.ofNatCore_val_eq _
    have hv' : v'.val = v.val + 1 := UScalar.ofNatCore_val_eq _
    have htotal : stride * n = ok total := scalar_mul_ok stride n (by rw [hproduct]; scalar_tac)
    have htwice : 2#usize * half = ok twice := scalar_mul_ok 2#usize half (by scalar_tac)
    have hinc : v + 1#usize = ok v' := scalar_add_ok v 1#usize (by scalar_tac)
    obtain ⟨step, hdiv, hstepval⟩ := UScalar.div_spec total (y := twice) (by omega)
    rw [htval, htwoval] at hstepval
    have hstep : 0 < step.val := by
      rw [hstepval]
      exact Nat.div_pos (by omega) (by omega)
    have hbound (lane : Fin 8) : (v.val + lane.val % (1#usize).val) * step.val < roots.size := by
      simp only [UScalar.ofNatCore_val_eq, Nat.mod_one, Nat.add_zero]
      rw [hstepval]
      have hsmall : v.val < 2 * half.val := by omega
      have hle := Nat.div_mul_le_self roots.size (2 * half.val)
      have hlt := Nat.mul_lt_mul_of_pos_right hsmall hstep
      rw [hstepval] at hlt
      exact lt_of_lt_of_le hlt (by simpa only [Nat.mul_comm] using hle)
    obtain ⟨twiddles, htwiddles, htw⟩ := stage_twiddles_refinement input roots hinput
      step v 1#usize hstep (by decide) hbound
    obtain ⟨factor, hload, hfactor⟩ := load_multiplier_refinement
      (Array.to_slice twiddles) 0#usize
      (fun _ => roots[v.val * (roots.size / (2 * half.val))]!)
      (by simp [Array.to_slice, twiddles.property]) (by
        intro lane
        simpa only [Array.to_slice, UScalar.ofNatCore_val_eq, Nat.zero_add,
          hstepval, Nat.mod_one, Nat.add_zero] using htw lane)
    have hpushBound : short.val.length + 1 ≤ Usize.max := by rw [hp.1]; scalar_tac
    let next : alloc.vec.Vec fr8.Fr8 := ⟨short.val ++ [factor], by simpa using hpushBound⟩
    have hpush : alloc.vec.Vec.push short factor = ok next := by
      simp [alloc.vec.Vec.push, hpushBound, next]
    have hprefix : ShortStagePrefix next roots half.val v'.val := by
      refine ⟨by simp [next, hp.1, hv', Nat.add_assoc], ?_⟩
      intro j
      by_cases hj : j.val < v.val
      · change MultiplierRep (short.val ++ [factor])[half.val - 1 + j.val]! _
        rw [List.getElem!_append_left _ _ _ (by rw [hp.1]; omega)]
        exact hp.2 ⟨j.val, hj⟩
      · have he : j.val = v.val := by omega
        change MultiplierRep (short.val ++ [factor])[half.val - 1 + j.val]! _
        rw [List.getElem!_append_right _ _ _ (by rw [hp.1, he])]
        simpa only [hp.1, he, Nat.sub_self, List.getElem!_cons_zero] using hfactor
    obtain ⟨out, hout, ho, hframe⟩ := ih next v' (by omega) hprefix (by omega)
    refine ⟨out, ?_, ho, ?_⟩
    · have hbody : fft8.Fft8.new_loop0_loop0.body input n stride half short v = ok (cont (next, v')) := by
        simp only [fft8.Fft8.new_loop0_loop0.body, bind_tc_ok,
          UScalar.lt_equiv, hvt, if_true, htotal, htwice, hdiv,
          htwiddles, lift, hload, hpush, hinc]
      rw [fft8.Fft8.new_loop0_loop0, loop.eq_1]
      simpa only [hbody] using hout
    · intro i hi
      rw [hframe i hi]
      exact List.getElem!_append_left _ _ _ (by rw [hp.1]; omega)

theorem short_stage_refinement
    (input : Slice blst.blst_fr) (roots : _root_.Array Fr)
    (hinput : input.val = roots.toList.map frEncode) (n stride half : Usize)
    (hproduct : stride.val * n.val = roots.size)
    (hhalf : 0 < half.val) (hhalfMax : half.val ≤ 4) (hhalfN : 2 * half.val ≤ n.val)
    (hn : n.val ≤ 4096) (hrootN : n.val ≤ roots.size)
    (short : alloc.vec.Vec fr8.Fr8) (hlen : short.val.length = half.val - 1) :
    ∃ out, fft8.Fft8.new_loop0_loop0 input n stride short half 0#usize = ok out ∧
      out.val.length = half.val - 1 + half.val ∧
      (∀ v : Fin (half.val), MultiplierRep out.val[half.val - 1 + v.val]!
        (fun _ => roots[v.val * (roots.size / (2 * half.val))]!)) ∧
      ∀ i, i < half.val - 1 → out.val[i]! = short.val[i]! := by
  obtain ⟨out, hout, hp, hframe⟩ := short_stage_loop input roots hinput n stride half
    hproduct hhalf hhalfMax hhalfN hn hrootN short 0#usize (by simp)
    ⟨by simpa using hlen, fun v => v.elim0⟩
  exact ⟨out, hout, hp.1, hp.2, hframe⟩

end LeanBlsSimd.Kzg.Extender.Kernel
