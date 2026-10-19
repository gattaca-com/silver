import LeanBlsSimd.Kzg.Extender.Kernel.Fr8
import LeanBlsSimd.Kzg.Extender.Decode
import LeanBlsSimd.Kzg.Extender.Kernel.FftTableBuild

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg
open scoped EthCryptographySpecs.Bls.Fr
open silver_crypto_simd silver_crypto_simd.kzg

attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero

namespace LeanBlsSimd.Kzg.Extender.Kernel

private theorem pow_div_eight (stage : Nat) (hs : 3 ≤ stage) :
    2 ^ stage / 8 = 2 ^ (stage - 3) := by
  conv_lhs => rw [show stage = (stage - 3) + 3 by omega, Nat.pow_add]
  simp

private theorem wide_index_lt (stage limit : Nat) (hs : 3 ≤ stage) (hl : stage < limit)
    (v : Fin (2 ^ stage / 8)) : 2 ^ stage / 8 - 1 + v.val < 2 ^ limit / 8 - 1 := by
  have hpositive : 0 < 2 ^ (stage - 3) := by positivity
  have hbound : 2 ^ (stage - 3) * 2 ≤ 2 ^ (limit - 3) := by
    rw [← Nat.pow_succ]
    exact Nat.pow_le_pow_right (by decide) (by omega)
  have hv : v.val < 2 ^ (stage - 3) := by simpa only [pow_div_eight stage hs] using v.isLt
  simp only [pow_div_eight stage hs, pow_div_eight limit (by omega)]
  omega

private def WideTables (wide : alloc.vec.Vec fr8.Fr8) (roots : _root_.Array Fr)
    (limit : Nat) : Prop :=
  wide.val.length = 2 ^ limit / 8 - 1 ∧
    ∀ stage, 3 ≤ stage → stage < limit → ∀ v : Fin (2 ^ stage / 8),
      MultiplierRep wide.val[2 ^ stage / 8 - 1 + v.val]!
        (fun lane => roots[(8 * v.val + lane.val) * (roots.size / (2 * 2 ^ stage))]!)

private theorem wide_tables_loop [e : KzgExternals] (hblst : BlstCorrect e)
    (input : Slice blst.blst_fr) (roots : _root_.Array Fr)
    (hinput : input.val = roots.toList.map frEncode) (n stride : Usize) (logSize : Nat)
    (hn : n.val = 2 ^ logSize) (hmax : logSize ≤ 12)
    (hproduct : stride.val * n.val = roots.size) (hrootN : n.val ≤ roots.size)
    (stage : Nat) (hs : 3 ≤ stage) (hsk : stage ≤ logSize)
    (wide : alloc.vec.Vec fr8.Fr8) (half : Usize) (hh : half.val = 2 ^ stage)
    (hw : WideTables wide roots stage) :
    ∃ out, fft8.Fft8.new_loop0 input n stride wide half = ok out ∧
      WideTables out roots logSize := by
  induction hrem : logSize - stage generalizing stage wide half with
  | zero =>
    have he : stage = logSize := by omega
    refine ⟨wide, ?_, by simpa only [he] using hw⟩
    rw [fft8.Fft8.new_loop0, loop.eq_1]
    simp [fft8.Fft8.new_loop0.body, UScalar.lt_equiv, hh, hn, he]
  | succ rem ih =>
    have hst : stage < logSize := by omega
    have hhalf : 8 ≤ half.val := by
      rw [hh]
      exact Nat.pow_le_pow_right (by decide : 0 < 2) hs
    have hhalfN : 2 * half.val ≤ n.val := by
      rw [hh, hn, Nat.mul_comm 2, ← Nat.pow_succ]
      exact Nat.pow_le_pow_right (by decide) (by omega)
    have hnmax : n.val ≤ 4096 := by
      rw [hn]
      exact Nat.pow_le_pow_right (by decide) hmax
    obtain ⟨next, hstage, hlen, hnew, hframe⟩ := wide_stage_refinement hblst input roots hinput
      n stride half hproduct hhalf hhalfN hnmax hrootN wide (by simpa only [hh] using hw.1)
    let half' : Usize := UScalar.ofNatCore (half.val * 2) (by scalar_tac)
    have hh' : half'.val = 2 ^ (stage + 1) := by
      simp only [half', UScalar.ofNatCore_val_eq, hh, Nat.pow_succ]
    have hmul : half * 2#usize = ok half' := scalar_mul_ok half 2#usize (by scalar_tac)
    have hnext : WideTables next roots (stage + 1) := by
      refine ⟨?_, ?_⟩
      · rw [hlen, hh, pow_div_eight stage hs, pow_div_eight (stage + 1) (by omega)]
        rw [show stage + 1 - 3 = (stage - 3) + 1 by omega, Nat.pow_succ]
        have : 0 < 2 ^ (stage - 3) := by positivity
        omega
      · intro s hs3 hslt v
        by_cases hss : s < stage
        · rw [hframe _ (by rw [hh]; exact wide_index_lt s stage hs3 hss v)]
          exact hw.2 s hs3 hss v
        · have he : s = stage := by omega
          subst s
          simpa only [hh] using hnew ⟨v.val, by simpa only [hh] using v.isLt⟩
    obtain ⟨out, hout, ho⟩ := ih (stage + 1) (by omega) (by omega) next half' hh' hnext (by omega)
    refine ⟨out, ?_, ho⟩
    have hlt : half < n := by
      simp only [UScalar.lt_equiv, hh, hn]
      exact Nat.pow_lt_pow_right (by decide) hst
    have hbody : fft8.Fft8.new_loop0.body input n stride wide half = ok (cont (next, half')) := by
      simp only [fft8.Fft8.new_loop0.body, hlt, if_true, hstage, hmul, bind_tc_ok]
    rw [fft8.Fft8.new_loop0, loop.eq_1]
    simpa only [hbody] using hout

private theorem sampled_twiddle (roots : _root_.Array Fr) (n d i : Nat)
    (hn : 0 < n) (hd : 0 < d) (hdiv : d ∣ n) (hrootDiv : n ∣ roots.size)
    (hi : i < d) :
    (sampleRoots roots n)[i * (n / d)]! = roots[i * (roots.size / d)]! := by
  have hdn : d ≤ n := Nat.le_of_dvd hn hdiv
  have hquot : 0 < n / d := Nat.div_pos hdn hd
  have hib : i * (n / d) < n := by
    calc
      i * (n / d) < d * (n / d) := Nat.mul_lt_mul_of_pos_right hi hquot
      _ = n := Nat.mul_div_cancel' hdiv
  have hrprod : roots.size = roots.size / n * n := (Nat.div_mul_cancel hrootDiv).symm
  have hstep : roots.size / d = (n / d) * (roots.size / n) := by
    conv_lhs => rw [hrprod, Nat.mul_div_assoc _ hdiv]
    exact Nat.mul_comm _ _
  simp only [sampleRoots, _root_.Array.getElem!_ofFn, hib]
  rw [hstep, Nat.mul_assoc]

theorem fft_new_refinement [e : KzgExternals] (hblst : BlstCorrect e)
    (input : Slice blst.blst_fr) (roots : _root_.Array Fr) (n : Usize)
    (hn : TransformSize n.val) (hroots : 0 < roots.size) (hdiv : roots.size % n.val = 0)
    (hinput : input.val = roots.toList.map frEncode) :
    ∃ table, fft8.Fft8.new input n = ok table ∧ FftInvariant table (sampleRoots roots n.val) := by
  obtain ⟨logSize, hk4, hk12, hnpow⟩ := hn
  have hnpos : 0 < n.val := by rw [hnpow]; positivity
  have hdiv' : n.val ∣ roots.size := Nat.dvd_of_mod_eq_zero hdiv
  have hrootN : n.val ≤ roots.size := Nat.le_of_dvd hroots hdiv'
  have hlen : input.val.length = roots.size := by
    simp only [hinput, List.length_map, _root_.Array.length_toList]
  have hmax : roots.size ≤ Usize.max := hlen ▸ input.property
  have hlenVal : (Slice.len input).val = roots.size := by
    simpa only [Slice.len, UScalar.ofNatCore_val_eq] using hlen
  obtain ⟨stride, hstride, hstrideval⟩ := UScalar.div_spec (Slice.len input) (y := n) (by omega)
  rw [hlenVal] at hstrideval
  have hproduct : stride.val * n.val = roots.size := by
    rw [hstrideval]
    exact Nat.div_mul_cancel hdiv'
  obtain ⟨vectors, hvectors, hvval⟩ := UScalar.div_spec n (y := fr8.LANES) (by simp [fr8.LANES])
  simp only [fr8.LANES, UScalar.ofNatCore_val_eq] at hvval
  let empty := alloc.vec.Vec.with_capacity fr8.Fr8 vectors
  have hempty : WideTables empty roots 3 := by
    refine ⟨rfl, ?_⟩
    intro stage hs ht
    omega
  obtain ⟨wide, hwide, hw⟩ := wide_tables_loop hblst input roots hinput n stride logSize
    hnpow hk12 hproduct hrootN 3 (by decide) (by omega) empty fr8.LANES
    (by simp [fr8.LANES]) hempty
  let total : Usize := UScalar.ofNatCore (stride.val * n.val) (by rw [hproduct]; scalar_tac)
  have htval : total.val = roots.size := by simp only [total, UScalar.ofNatCore_val_eq, hproduct]
  have htotal : stride * n = ok total := scalar_mul_ok stride n (by rw [hproduct]; scalar_tac)
  obtain ⟨step2, hs2, hs2val⟩ := UScalar.div_spec total (y := 4#usize) (by simp)
  obtain ⟨step4, hs4, hs4val⟩ := UScalar.div_spec total (y := 8#usize) (by simp)
  simp only [htval, UScalar.ofNatCore_val_eq] at hs2val hs4val
  have hn16 : 16 ≤ n.val := by
    rw [hnpow]
    exact Nat.pow_le_pow_right (by decide : 0 < 2) hk4
  have hstep2 : 0 < step2.val := by rw [hs2val]; exact Nat.div_pos (by omega) (by decide)
  have hstep4 : 0 < step4.val := by rw [hs4val]; exact Nat.div_pos (by omega) (by decide)
  have hbound2 (lane : Fin 8) : ((0#usize).val + lane.val % (2#usize).val) * step2.val < roots.size := by
    simp only [UScalar.ofNatCore_val_eq, Nat.zero_add]
    have ht : lane.val % 2 < 4 := by omega
    have hlt := Nat.mul_lt_mul_of_pos_right ht hstep2
    have hle := Nat.div_mul_le_self roots.size 4
    rw [hs2val] at hlt ⊢
    exact lt_of_lt_of_le hlt (by simpa only [Nat.mul_comm] using hle)
  have hbound4 (lane : Fin 8) : ((0#usize).val + lane.val % (4#usize).val) * step4.val < roots.size := by
    simp only [UScalar.ofNatCore_val_eq, Nat.zero_add]
    have ht : lane.val % 4 < 8 := by omega
    have hlt := Nat.mul_lt_mul_of_pos_right ht hstep4
    have hle := Nat.div_mul_le_self roots.size 8
    rw [hs4val] at hlt ⊢
    exact lt_of_lt_of_le hlt (by simpa only [Nat.mul_comm] using hle)
  obtain ⟨twiddles2, ht2, htv2⟩ := stage_twiddles_refinement hblst input roots hinput step2
    0#usize 2#usize hstep2 (by decide) hbound2
  obtain ⟨twiddles4, ht4, htv4⟩ := stage_twiddles_refinement hblst input roots hinput step4
    0#usize 4#usize hstep4 (by decide) hbound4
  obtain ⟨stage2, hl2, hr2⟩ := load_multiplier_refinement (Array.to_slice twiddles2) 0#usize
    (fun lane => roots[(lane.val % 2) * (roots.size / 4)]!)
    (by simp [Array.to_slice, twiddles2.property]) (by
      intro lane
      simpa only [Array.to_slice, UScalar.ofNatCore_val_eq, Nat.zero_add, hs2val] using htv2 lane)
  obtain ⟨stage4, hl4, hr4⟩ := load_multiplier_refinement (Array.to_slice twiddles4) 0#usize
    (fun lane => roots[(lane.val % 4) * (roots.size / 8)]!)
    (by simp [Array.to_slice, twiddles4.property]) (by
      intro lane
      simpa only [Array.to_slice, UScalar.ofNatCore_val_eq, Nat.zero_add, hs4val] using htv4 lane)
  let table : fft8.Fft8 := ⟨vectors, wide, stage2, stage4⟩
  refine ⟨table, ?_, ?_⟩
  · obtain ⟨sub, hsub, hsubval, _⟩ := WP.spec_imp_exists
      (Usize.sub_spec (x := n) (y := 1#usize) (by simp only [UScalar.ofNatCore_val_eq]; omega))
    have hand : n &&& sub = 0#usize := by
      apply UScalar.eq_of_val_eq
      simp only [UScalar.val_and, hnpow, hsubval, UScalar.ofNatCore_val_eq]
      simp
    obtain ⟨rem, hrem, hremval⟩ := WP.spec_imp_exists
      (UScalar.rem_spec (Slice.len input) (y := n) (by omega))
    have he : rem = 0#usize := UScalar.eq_of_val_eq (by simpa only [hlenVal, hdiv, UScalar.ofNatCore_val_eq] using hremval)
    subst rem
    have htwice : 2#usize * fr8.LANES = ok 16#usize := by
      simpa only [fr8.LANES] using scalar_mul_ok 2#usize 8#usize (by scalar_tac)
    have hge : n ≥ 16#usize := by simpa only [UScalar.le_equiv, UScalar.ofNatCore_val_eq] using hn16
    dsimp only [empty] at hwide
    simp only [fft8.Fft8.new, htwice, hge, massert, if_true, bind_tc_ok,
      hsub, lift, hand, hrem, hstride, hvectors, hwide, htotal, hs2, ht2, hs4, ht4,
      hl2, hl4, table]
  · have hsize : (sampleRoots roots n.val).size = n.val := _root_.Array.size_ofFn
    refine ⟨by rw [hsize]; exact ⟨logSize, hk4, hk12, hnpow⟩,
      by simpa only [table, hsize] using hvval,
      by simpa only [table, sampleRoots, _root_.Array.size_ofFn, hnpow] using hw.1, ?_, ?_, ?_⟩
    · intro stage hs hb v
      have hsk : stage < logSize := by
        have h := hb
        rw [hsize, hnpow] at h
        exact (Nat.pow_lt_pow_iff_right (by decide : 1 < 2)).mp h
      have hd : 2 * 2 ^ stage ∣ n.val := by
        rw [hnpow, Nat.mul_comm 2, ← Nat.pow_succ]
        exact Nat.pow_dvd_pow 2 (by omega)
      have hfn : (fun lane : Fin 8 => (sampleRoots roots n.val)[
          (8 * v.val + lane.val) * ((sampleRoots roots n.val).size / (2 * 2 ^ stage))]!) =
          (fun lane : Fin 8 => roots[(8 * v.val + lane.val) * (roots.size / (2 * 2 ^ stage))]!) := by
        funext lane
        rw [hsize]
        exact sampled_twiddle roots n.val (2 * 2 ^ stage) (8 * v.val + lane.val) hnpos
          (by positivity) hd hdiv' (by have := v.isLt; omega)
      rw [hfn]
      exact hw.2 stage hs hsk v
    · have hd : 4 ∣ n.val := by
        rw [hnpow]
        exact Nat.pow_dvd_pow 2 (by omega : 2 ≤ logSize)
      have hfn : (fun lane : Fin 8 => (sampleRoots roots n.val)[
          (lane.val % 2) * ((sampleRoots roots n.val).size / 4)]!) =
          (fun lane : Fin 8 => roots[(lane.val % 2) * (roots.size / 4)]!) := by
        funext lane
        rw [hsize]
        exact sampled_twiddle roots n.val 4 (lane.val % 2) hnpos (by decide) hd hdiv' (by omega)
      rw [hfn]
      exact hr2
    · have hd : 8 ∣ n.val := by
        rw [hnpow]
        exact Nat.pow_dvd_pow 2 (by omega : 3 ≤ logSize)
      have hfn : (fun lane : Fin 8 => (sampleRoots roots n.val)[
          (lane.val % 4) * ((sampleRoots roots n.val).size / 8)]!) =
          (fun lane : Fin 8 => roots[(lane.val % 4) * (roots.size / 8)]!) := by
        funext lane
        rw [hsize]
        exact sampled_twiddle roots n.val 8 (lane.val % 4) hnpos (by decide) hd hdiv' (by omega)
      rw [hfn]
      exact hr4

end LeanBlsSimd.Kzg.Extender.Kernel
