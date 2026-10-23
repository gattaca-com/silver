import LeanBlsSimd.Kzg.Extender.Kernel.Fr8
import LeanBlsSimd.Kzg.Extender.Decode
import LeanBlsSimd.Kzg.Extender.Kernel.FftTableBuild

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open scoped EthLib.Cryptography.Bls.Fr
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

private theorem wide_tables_loop
    (input : Slice blst.blst_fr) (roots : _root_.Array Fr)
    (hinput : input.val = roots.toList.map frEncode) (n stride : Usize) (logSize : Nat)
    (hn : n.val = 2 ^ logSize) (hmax : logSize ≤ 12)
    (hproduct : stride.val * n.val = roots.size) (hrootN : n.val ≤ roots.size)
    (stage : Nat) (hs : 3 ≤ stage) (hsk : stage ≤ logSize)
    (wide : alloc.vec.Vec fr8.Fr8) (half : Usize) (hh : half.val = 2 ^ stage)
    (hw : WideTables wide roots stage) :
    ∃ out, fft8.Fft8.new_loop1 input n stride wide half = ok out ∧
      WideTables out roots logSize := by
  induction hrem : logSize - stage generalizing stage wide half with
  | zero =>
    have he : stage = logSize := by omega
    refine ⟨wide, ?_, by simpa only [he] using hw⟩
    rw [fft8.Fft8.new_loop1, loop.eq_1]
    simp [fft8.Fft8.new_loop1.body, UScalar.lt_equiv, hh, hn, he]
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
    obtain ⟨next, hstage, hlen, hnew, hframe⟩ := wide_stage_refinement input roots hinput
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
    have hbody : fft8.Fft8.new_loop1.body input n stride wide half = ok (cont (next, half')) := by
      simp only [fft8.Fft8.new_loop1.body, hlt, if_true, hstage, hmul, bind_tc_ok]
    rw [fft8.Fft8.new_loop1, loop.eq_1]
    simpa only [hbody] using hout

private theorem short_tables_refinement
    (input : Slice blst.blst_fr) (roots : _root_.Array Fr)
    (hinput : input.val = roots.toList.map frEncode) (n stride : Usize)
    (hproduct : stride.val * n.val = roots.size) (hnmin : 64 ≤ n.val)
    (hnmax : n.val ≤ 4096) (hrootN : n.val ≤ roots.size) :
    ∃ short, fft8.Fft8.new_loop0 input n stride
        (alloc.vec.Vec.with_capacity fr8.Fr8 7#usize) 1#usize = ok short ∧
      short.val.length = 7 ∧
      ∀ h : Nat, h = 1 ∨ h = 2 ∨ h = 4 → ∀ j : Fin h,
        MultiplierRep short.val[h - 1 + j.val]!
          (fun _ => roots[j.val * (roots.size / (2 * h))]!) := by
  obtain ⟨s1, hs1, hl1, hr1, _⟩ := short_stage_refinement input roots hinput n stride
    1#usize hproduct (by decide) (by decide) (by simpa using (show 2 ≤ n.val by omega))
    hnmax hrootN (alloc.vec.Vec.with_capacity fr8.Fr8 7#usize) rfl
  obtain ⟨s2, hs2, hl2, hr2, hf2⟩ := short_stage_refinement input roots hinput n stride
    2#usize hproduct (by decide) (by decide) (by simpa using (show 4 ≤ n.val by omega))
    hnmax hrootN s1 (by simpa using hl1)
  obtain ⟨s4, hs4, hl4, hr4, hf4⟩ := short_stage_refinement input roots hinput n stride
    4#usize hproduct (by decide) (by decide) (by simpa using (show 8 ≤ n.val by omega))
    hnmax hrootN s2 (by simpa using hl2)
  have hm1 : 1#usize * 2#usize = ok 2#usize := by
    simpa using scalar_mul_ok 1#usize 2#usize (by scalar_tac)
  have hm2 : 2#usize * 2#usize = ok 4#usize := by
    simpa using scalar_mul_ok 2#usize 2#usize (by scalar_tac)
  have hm4 : 4#usize * 2#usize = ok 8#usize := by
    simpa using scalar_mul_ok 4#usize 2#usize (by scalar_tac)
  have hstop : fft8.Fft8.new_loop0 input n stride s4 8#usize = ok s4 := by
    rw [fft8.Fft8.new_loop0, loop.eq_1]
    simp [fft8.Fft8.new_loop0.body, fr8.LANES]
  have hloop4 : fft8.Fft8.new_loop0 input n stride s2 4#usize = ok s4 := by
    have hbody : fft8.Fft8.new_loop0.body input n stride s2 4#usize =
        ok (cont (s4, 8#usize)) := by
      simp only [fft8.Fft8.new_loop0.body, fr8.LANES, UScalar.lt_equiv,
        UScalar.ofNatCore_val_eq, show 4 < 8 by decide, if_true, hs4, hm4, bind_tc_ok]
    rw [fft8.Fft8.new_loop0, loop.eq_1]
    simpa only [hbody] using hstop
  have hloop2 : fft8.Fft8.new_loop0 input n stride s1 2#usize = ok s4 := by
    have hbody : fft8.Fft8.new_loop0.body input n stride s1 2#usize =
        ok (cont (s2, 4#usize)) := by
      simp only [fft8.Fft8.new_loop0.body, fr8.LANES, UScalar.lt_equiv,
        UScalar.ofNatCore_val_eq, show 2 < 8 by decide, if_true, hs2, hm2, bind_tc_ok]
    rw [fft8.Fft8.new_loop0, loop.eq_1]
    simpa only [hbody] using hloop4
  refine ⟨s4, ?_, by simpa using hl4, ?_⟩
  · have hbody : fft8.Fft8.new_loop0.body input n stride (alloc.vec.Vec.with_capacity fr8.Fr8 7#usize) 1#usize =
        ok (cont (s1, 2#usize)) := by
      simp only [fft8.Fft8.new_loop0.body, fr8.LANES, UScalar.lt_equiv,
        UScalar.ofNatCore_val_eq, show 1 < 8 by decide, if_true, hs1, hm1, bind_tc_ok]
    rw [fft8.Fft8.new_loop0, loop.eq_1]
    simpa only [hbody] using hloop2
  · intro h hh j
    rcases hh with rfl | rfl | rfl
    · rw [hf4 _ (by have := j.isLt; simp only [UScalar.ofNatCore_val_eq]; omega),
        hf2 _ (by have := j.isLt; simp only [UScalar.ofNatCore_val_eq]; omega)]
      exact hr1 j
    · rw [hf4 _ (by have := j.isLt; simp only [UScalar.ofNatCore_val_eq]; omega)]
      exact hr2 j
    · exact hr4 j

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

theorem fft_new_refinement
    (input : Slice blst.blst_fr) (roots : _root_.Array Fr) (n : Usize)
    (hn : TransformSize n.val) (hroots : 0 < roots.size) (hdiv : roots.size % n.val = 0)
    (hinput : input.val = roots.toList.map frEncode) :
    ∃ table, fft8.Fft8.new input n = ok table ∧ FftInvariant table (sampleRoots roots n.val) := by
  obtain ⟨logSize, hk6, hk12, hnpow⟩ := hn
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
  obtain ⟨wide, hwide, hw⟩ := wide_tables_loop input roots hinput n stride logSize
    hnpow hk12 hproduct hrootN 3 (by decide) (by omega) empty fr8.LANES
    (by simp [fr8.LANES]) hempty
  have hn64 : 64 ≤ n.val := by
    rw [hnpow]
    exact Nat.pow_le_pow_right (by decide : 0 < 2) hk6
  have hnmax : n.val ≤ 4096 := by
    rw [hnpow]
    exact Nat.pow_le_pow_right (by decide : 0 < 2) hk12
  obtain ⟨short, hshort, hshortlen, hshortrep⟩ := short_tables_refinement input roots
    hinput n stride hproduct hn64 hnmax hrootN
  let table : fft8.Fft8 := ⟨vectors, wide, short⟩
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
    have hblock : fr8.LANES * fr8.LANES = ok 64#usize := by
      simpa only [fr8.LANES] using scalar_mul_ok 8#usize 8#usize (by scalar_tac)
    have hcapacity : fr8.LANES - 1#usize = ok 7#usize := by
      obtain ⟨capacity, hc, hcv, _⟩ := WP.spec_imp_exists
        (Usize.sub_spec (x := fr8.LANES) (y := 1#usize) (by simp [fr8.LANES]))
      have heq : capacity = 7#usize := UScalar.eq_of_val_eq (by simpa [fr8.LANES] using hcv)
      simpa only [heq] using hc
    have hge : n ≥ 64#usize := by simpa only [UScalar.le_equiv, UScalar.ofNatCore_val_eq] using hn64
    have hle : n ≤ 4096#usize := by
      simpa only [UScalar.le_equiv, UScalar.ofNatCore_val_eq] using hnmax
    have hshift : 1#usize <<< 12#i32 = ok 4096#usize := by
      have hbits := System.Platform.le_numBits
      obtain ⟨shift, hs, hv, _⟩ := WP.spec_imp_exists
        (Usize.ShiftLeft_IScalar_spec 1#usize 12#i32 (by scalar_tac) (by scalar_tac))
      have he : shift = 4096#usize := by
        apply UScalar.eq_of_val_eq
        simpa [IScalar.toNat, Nat.mod_eq_of_lt (show 4096 < Usize.size by scalar_tac)] using hv
      simpa only [he] using hs
    dsimp only [empty] at hwide
    simp only [fft8.Fft8.new, hblock, hge, hshift, hle, massert, if_true, bind_tc_ok,
      hsub, lift, hand, hrem, hstride, hvectors, hwide, hcapacity, hshort, table]
  · have hsize : (sampleRoots roots n.val).size = n.val := _root_.Array.size_ofFn
    refine ⟨by rw [hsize]; exact ⟨logSize, hk6, hk12, hnpow⟩,
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
    · exact hshortlen
    · intro h hh j
      have hd : 2 * h ∣ n.val := by
        rw [hnpow]
        rcases hh with rfl | rfl | rfl
        · exact Nat.pow_dvd_pow 2 (by omega : 1 ≤ logSize)
        · exact Nat.pow_dvd_pow 2 (by omega : 2 ≤ logSize)
        · exact Nat.pow_dvd_pow 2 (by omega : 3 ≤ logSize)
      have hp : 0 < h := by rcases hh with rfl | rfl | rfl <;> decide
      have hfn : (fun _ : Fin 8 => (sampleRoots roots n.val)[
          j.val * ((sampleRoots roots n.val).size / (2 * h))]!) =
          (fun _ : Fin 8 => roots[j.val * (roots.size / (2 * h))]!) := by
        funext lane
        rw [hsize]
        exact sampled_twiddle roots n.val (2 * h) j.val hnpos (by omega) hd hdiv' (by omega)
      rw [hfn]
      exact hshortrep h hh j

end LeanBlsSimd.Kzg.Extender.Kernel
