import LeanBlsSimd.Kzg.Extender.Kernel.Fr8
import LeanBlsSimd.Kzg.Extender.Kernel.FftTables
import LeanBlsSimd.Kzg.Extender.Kernel.FftMath
import LeanBlsSimd.Kzg.Extender.Kernel.FftWide
import LeanBlsSimd.Kzg.Extender.Kernel.FftBlocks
import LeanBlsSimd.Kzg.Extender.Decode

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg Kzg.BitReversal
open scoped EthCryptographySpecs.Bls.Fr
open silver_crypto_simd silver_crypto_simd.kzg

attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero

namespace LeanBlsSimd.Kzg.Extender.Kernel

set_option maxRecDepth 10000
set_option maxHeartbeats 4000000

@[simp] theorem size_butterflyStage (dit : Bool) (values roots : _root_.Array Fr) (h : Nat) :
    (butterflyStage dit values roots h).size = values.size := by
  simp only [butterflyStage, _root_.Array.size_ofFn]

private theorem table_vectors_le (table : fft8.Fft8) (roots : _root_.Array Fr)
    (htable : FftInvariant table roots) : table.vectors.val ≤ 512 := by
  obtain ⟨k, hk4, hk12, hk⟩ := htable.1
  have hle : roots.size ≤ 4096 := by rw [hk]; exact Nat.pow_le_pow_right (by decide) hk12
  rw [htable.2.1]
  omega

private theorem dit_wide_steps (table : fft8.Fft8) (roots : _root_.Array Fr)
    (htable : FftInvariant table roots) (remaining : Nat) :
    ∀ (s : Nat) (data : Slice fr8.Fr8) (values : _root_.Array Fr) (half : Usize),
      values.size = roots.size → LazyDataRep (16+2*s) (73+33*s) data values →
      half.val = 2 ^ s → table.vectors.val = 2 ^ (s + remaining) → s + remaining ≤ 9 →
      ∃ out,
        fft8.Fft8.dit_loop1 table.vectors table.wide table.short data half = ok out ∧
        LazyDataRep (16+2*(s+remaining)) (73+33*(s+remaining)) out ((List.range' (s + 3) remaining).foldl
          (fun acc stage => butterflyStage true acc roots (2 ^ stage)) values) := by
  intro s data values half hsize hdata hhalf hsteps hlimit
  induction remaining generalizing s data values half with
  | zero =>
    refine ⟨data, ?_, by simpa using hdata⟩
    rw [fft8.Fft8.dit_loop1, loop.eq_1]
    simp [fft8.Fft8.dit_loop1.body, UScalar.lt_equiv, hsteps, hhalf]
  | succ remaining ih =>
    have hp : 0 < 2 ^ s := by positivity
    have hrem : 1 ≤ 2 ^ remaining := Nat.one_le_two_pow
    have hlt : half.val < table.vectors.val := by
      rw [hhalf, hsteps, Nat.pow_add, Nat.pow_succ]
      nlinarith
    have hdbl : half.val * 2 ≤ table.vectors.val := by
      rw [hhalf, hsteps, Nat.pow_add, Nat.pow_succ]
      nlinarith
    have hsmall := table_vectors_le table roots htable
    let next : Usize := UScalar.ofNatCore (half.val * 2) (by scalar_tac)
    have hnext : next.val = half.val * 2 := UScalar.ofNatCore_val_eq _
    have hmul : half * 2#usize = ok next := by
      simpa only [next] using scalar_mul_ok half 2#usize (by scalar_tac)
    obtain ⟨stageData, hstage, hrep⟩ := wide_refinement true (16+2*s) (73+33*s)
      (by omega) (by omega) (by simp) table data half values roots
      htable hsize hdata ⟨s, hhalf⟩ hlt
    change fft8.Fft8.dit_wide table data half = ok stageData at hstage
    have hwidth : 8 * half.val = 2 ^ (s + 3) := by rw [hhalf, Nat.pow_add]; ring
    rw [hwidth] at hrep
    obtain ⟨out, hrun, hout⟩ := ih (s + 1) stageData
      (butterflyStage true values roots (2 ^ (s + 3))) next
      (by simpa using hsize) (by convert hrep using 1)
      (by rw [hnext, hhalf, Nat.pow_succ])
      (by simpa only [Nat.add_assoc, Nat.add_left_comm, Nat.add_comm] using hsteps)
      (by omega)
    refine ⟨out, ?_, ?_⟩
    · rw [fft8.Fft8.dit_loop1, loop.eq_1]
      simp only [fft8.Fft8.dit_loop1.body, UScalar.lt_equiv, hlt, if_true,
        hstage, bind_tc_ok, hmul]
      exact hrun
    · simpa only [List.range'_succ, List.foldl_cons, Nat.add_assoc,
        Nat.add_left_comm, Nat.add_comm] using hout

private theorem dif_wide_steps (table : fft8.Fft8) (roots : _root_.Array Fr)
    (htable : FftInvariant table roots) (remaining : Nat) :
    ∀ (data : Slice fr8.Fr8) (values : _root_.Array Fr) (half : Usize),
      values.size = roots.size → LazyDataRep 2 32 data values →
      half.val = 2 ^ remaining / 2 → 2 ^ remaining ≤ table.vectors.val →
      ∃ out,
        fft8.Fft8.dif_loop0 table.vectors table.wide table.short data half = ok out ∧
        LazyDataRep 2 32 out ((List.range' 3 remaining).reverse.foldl
          (fun acc stage => butterflyStage false acc roots (2 ^ stage)) values) := by
  intro data values half hsize hdata hhalf hsteps
  induction remaining generalizing data values half with
  | zero =>
    refine ⟨data, ?_, by simpa using hdata⟩
    rw [fft8.Fft8.dif_loop0, loop.eq_1]
    simp [fft8.Fft8.dif_loop0.body, UScalar.lt_equiv, hhalf]
  | succ remaining ih =>
    have hhalf' : half.val = 2 ^ remaining := by simpa [Nat.pow_succ] using hhalf
    have hp : 0 < half.val := by rw [hhalf']; positivity
    have hlt : half.val < table.vectors.val := by
      rw [hhalf']
      rw [Nat.pow_succ] at hsteps
      nlinarith [Nat.two_pow_pos remaining]
    obtain ⟨next, hdiv, hnext⟩ := UScalar.div_spec half (y := 2#usize) (by simp)
    obtain ⟨stageData, hstage, hrep⟩ := wide_refinement false 2 32 (by decide) (by decide) (by simp)
      table data half values roots htable hsize hdata ⟨remaining, hhalf'⟩ hlt
    change fft8.Fft8.dif_wide table data half = ok stageData at hstage
    have hwidth : 8 * half.val = 2 ^ (3 + remaining) := by rw [hhalf', Nat.pow_add]
    rw [hwidth] at hrep
    obtain ⟨out, hrun, hout⟩ := ih stageData
      (butterflyStage false values roots (2 ^ (3 + remaining))) next
      (by simpa using hsize) hrep
      (by simpa only [UScalar.ofNatCore_val_eq, hhalf'] using hnext)
      (by rw [Nat.pow_succ] at hsteps; nlinarith [Nat.two_pow_pos remaining])
    refine ⟨out, ?_, ?_⟩
    · rw [fft8.Fft8.dif_loop0, loop.eq_1]
      simp only [fft8.Fft8.dif_loop0.body, UScalar.lt_equiv, UScalar.ofNatCore_val_eq,
        hp, if_true, hstage, bind_tc_ok, hdiv]
      exact hrun
    · simpa only [List.range'_1_concat, List.reverse_append,
        List.reverse_cons, List.reverse_nil, List.nil_append, List.singleton_append,
        List.foldl_cons] using hout

private theorem range_split_three (k : Nat) (hk : 3 ≤ k) :
    List.range k = [0, 1, 2] ++ List.range' 3 (k - 3) := by
  conv_lhs => rw [show k = 3 + (k - 3) by omega, List.range_eq_range', ← List.range'_append]
  rfl

theorem dit_stages_refinement (table : fft8.Fft8) (data : Slice fr8.Fr8)
    (values roots : _root_.Array Fr) (logSize : Nat)
    (htable : FftInvariant table roots) (hsize : values.size = roots.size)
    (hlog : roots.size = 2 ^ logSize) (hunit : roots[0]! = 1) (hdata : DataRep data values) :
    ∃ out, fft8.Fft8.dit table data = ok out ∧
      LazyDataRep (16+2*(logSize-3)) (73+33*(logSize-3)) out (iterativeDit logSize values roots) := by
  have hlogBounds : 6 ≤ logSize ∧ logSize ≤ 12 := by
    obtain ⟨k, hk4, hk12, hn⟩ := htable.1
    have heq : k = logSize := Nat.pow_right_injective (by decide) (hn.symm.trans hlog)
    omega
  have hk := hlogBounds.1
  have hvectors : table.vectors.val = 2 ^ (logSize - 3) := by
    rw [htable.2.1, hlog]
    conv_lhs => rw [show logSize = (logSize - 3) + 3 by omega, Nat.pow_add]
    simp
  have hlen : Slice.len data = table.vectors := by
    apply UScalar.eq_of_val_eq
    simp only [Slice.len, Usize.ofNatCore_val_eq]
    rw [htable.2.1, ← hsize, hdata.1]
    omega
  obtain ⟨d3, hd3, hr3⟩ := blocks_refinement true table data values roots
    htable hsize hunit hdata
  change fft8.Fft8.dit_loop0 table.vectors table.wide table.short data 0#usize = ok d3 at hd3
  obtain ⟨out, hout, hrep⟩ := dit_wide_steps table roots htable (logSize - 3) 0 d3
    (shortStages true values roots) 1#usize
    (by simpa using hsize) hr3 (by simp) (by simpa using hvectors) (by omega)
  refine ⟨out, ?_, ?_⟩
  · unfold fft8.Fft8.dit
    simpa only [hlen, massert, if_true, bind_tc_ok, hd3] using hout
  · simpa [iterativeDit, range_split_three logSize (by omega), List.foldl_append,
      shortStages] using hrep


theorem dif_stages_refinement (table : fft8.Fft8) (data : Slice fr8.Fr8)
    (values roots : _root_.Array Fr) (logSize : Nat)
    (htable : FftInvariant table roots) (hsize : values.size = roots.size)
    (hlog : roots.size = 2 ^ logSize) (hunit : roots[0]! = 1) (hdata : LazyDataRep 2 32 data values) :
    ∃ out, fft8.Fft8.dif table data = ok out ∧ DataRep out (iterativeDif logSize values roots) := by
  have hk : 4 ≤ logSize := by
    obtain ⟨k, hk4, hk12, hn⟩ := htable.1
    have heq : k = logSize := Nat.pow_right_injective (by decide) (hn.symm.trans hlog)
    omega
  have hvectors : table.vectors.val = 2 ^ (logSize - 3) := by
    rw [htable.2.1, hlog]
    conv_lhs => rw [show logSize = (logSize - 3) + 3 by omega, Nat.pow_add]
    simp
  have hlen : Slice.len data = table.vectors := by
    apply UScalar.eq_of_val_eq
    simp only [Slice.len, Usize.ofNatCore_val_eq]
    rw [htable.2.1, ← hsize, hdata.1]
    omega
  obtain ⟨half, hdiv, hhalf⟩ := UScalar.div_spec table.vectors (y := 2#usize) (by simp)
  obtain ⟨d0, hd0, hr0⟩ := dif_wide_steps table roots htable (logSize - 3) data values half
    hsize hdata (by simpa only [hvectors, UScalar.ofNatCore_val_eq] using hhalf) (by rw [hvectors])
  let middle := (List.range' 3 (logSize - 3)).reverse.foldl
    (fun acc stage => butterflyStage false acc roots (2 ^ stage)) values
  have hmid : middle.size = roots.size := by
    suffices ∀ (stages : List Nat) (v : _root_.Array Fr),
        (stages.foldl (fun acc stage => butterflyStage false acc roots (2 ^ stage)) v).size = v.size by
      simpa [middle] using (this (List.range' 3 (logSize - 3)).reverse values).trans hsize
    intro stages
    induction stages with
    | nil => simp
    | cons stage stages ih => intro v; simp [ih]
  obtain ⟨out, hout, hrep⟩ := blocks_refinement false table d0 middle roots
    htable hmid hunit hr0
  refine ⟨out, ?_, ?_⟩
  · unfold fft8.Fft8.dif
    simpa only [hlen, massert, if_true, bind_tc_ok, hdiv, hd0,
      Bool.false_eq_true, if_false] using hout
  · simpa [iterativeDif, range_split_three logSize (by omega), List.foldl_append,
      List.reverse_append, middle, shortStages] using hrep


theorem iterative_dit_eq_spec (values roots : _root_.Array Fr) (logSize : Nat)
    (hn : TransformSize roots.size) (hsize : values.size = roots.size)
    (hlog : roots.size = 2 ^ logSize) (hroots : RootsValid roots) :
    iterativeDit logSize values roots = fftFieldAux (bitReversalPermutation values) roots := by
  obtain ⟨_, _, _, _⟩ := hn
  exact iterative_dit_eq_spec_pow values roots logSize hsize hlog hroots

theorem iterative_dif_eq_spec (values roots : _root_.Array Fr) (logSize : Nat)
    (hn : TransformSize roots.size) (hsize : values.size = roots.size)
    (hlog : roots.size = 2 ^ logSize) (hroots : RootsValid roots) :
    iterativeDif logSize values roots = bitReversalPermutation (fftFieldAux values roots) := by
  obtain ⟨_, _, _, _⟩ := hn
  exact iterative_dif_eq_spec_pow values roots logSize hsize hlog hroots

theorem dit_refinement (table : fft8.Fft8) (data : Slice fr8.Fr8)
    (values roots : _root_.Array Fr) (htable : FftInvariant table roots)
    (hsize : values.size = roots.size) (hroots : RootsValid roots) (hdata : DataRep data values) :
    ∃ out, fft8.Fft8.dit table data = ok out ∧
      LazyDataRep 34 370 out (fftFieldAux (bitReversalPermutation values) roots) := by
  obtain ⟨ω, k, hrs, hω, hpow⟩ := hroots
  have hunit : roots[0]! = 1 := by
    simpa using hpow 0 (by rw [hrs]; positivity)
  obtain ⟨out, hout, hrep⟩ := dit_stages_refinement table data values roots k
    htable hsize hrs hunit hdata
  refine ⟨out, hout, ?_⟩
  rw [iterative_dit_eq_spec values roots k htable.1 hsize hrs
    ⟨ω, k, hrs, hω, hpow⟩] at hrep
  have hk : k ≤ 12 := by
    obtain ⟨logSize, _, hle, heq⟩ := htable.1
    have := Nat.pow_right_injective (by decide : 1 < 2) (heq.symm.trans hrs)
    omega
  exact hrep.mono (by omega) (by omega)

theorem dif_refinement (table : fft8.Fft8) (data : Slice fr8.Fr8)
    (values roots : _root_.Array Fr) (htable : FftInvariant table roots)
    (hsize : values.size = roots.size) (hroots : RootsValid roots) (hdata : LazyDataRep 2 32 data values) :
    ∃ out, fft8.Fft8.dif table data = ok out ∧
      DataRep out (bitReversalPermutation (fftFieldAux values roots)) := by
  obtain ⟨ω, k, hrs, hω, hpow⟩ := hroots
  have hunit : roots[0]! = 1 := by
    simpa using hpow 0 (by rw [hrs]; positivity)
  obtain ⟨out, hout, hrep⟩ := dif_stages_refinement table data values roots k
    htable hsize hrs hunit hdata
  refine ⟨out, hout, ?_⟩
  rw [iterative_dif_eq_spec values roots k htable.1 hsize hrs
    ⟨ω, k, hrs, hω, hpow⟩] at hrep
  exact hrep

theorem sampled_roots_valid (roots : _root_.Array Fr) (n : Nat)
    (hn : TransformSize n) (hroots : RootsValid roots)
    (hsize : 0 < roots.size) (hdiv : roots.size % n = 0) :
    RootsValid (sampleRoots roots n) := by
  obtain ⟨k, hk4, hk12, hn⟩ := hn
  obtain ⟨ω, l, hrs, hω, hroots⟩ := hroots
  have hnpos : 0 < n := by rw [hn]; positivity
  have hdiv' : n ∣ roots.size := Nat.dvd_of_mod_eq_zero hdiv
  have hprod : roots.size = roots.size / n * n := (Nat.div_mul_cancel hdiv').symm
  refine ⟨ω ^ (roots.size / n), k, ?_, ?_, ?_⟩
  · simpa only [sampleRoots, Array.size_ofFn] using hn
  · apply IsPrimitiveRoot.pow (by positivity : 0 < 2 ^ l) hω
    rw [← hrs, ← hn]
    exact hprod
  · intro i hi
    have hin : i < n := by simpa only [sampleRoots, Array.size_ofFn] using hi
    have hi' : i * (roots.size / n) < roots.size := by
      have hq : 0 < roots.size / n := by
        rw [hprod] at hsize
        exact Nat.pos_of_mul_pos_right hsize
      calc
        i * (roots.size / n) < n * (roots.size / n) := Nat.mul_lt_mul_of_pos_right hin hq
        _ = roots.size := by rw [Nat.mul_comm]; exact hprod.symm
    rw [getElem!_pos _ i hi]
    simp only [sampleRoots, _root_.Array.getElem_ofFn]
    rw [hroots _ hi', Nat.mul_comm i (roots.size / n), pow_mul]

theorem inverse_roots_valid (roots : _root_.Array Fr) (hroots : RootsValid roots) :
    RootsValid (Kzg.Model.inverseRoots roots) := by
  obtain ⟨ω, k, hrs, hω, hroots⟩ := hroots
  refine ⟨ω⁻¹, k, by simpa [Kzg.Model.inverseRoots] using hrs, hω.inv, ?_⟩
  intro i hi
  have hi' : i < roots.size := by simpa only [Kzg.Model.inverseRoots, Array.size_ofFn] using hi
  rw [getElem!_pos _ i hi]
  simp only [Kzg.Model.inverseRoots, _root_.Array.getElem_ofFn]
  by_cases hi0 : i = 0
  · subst i
    simp [hroots 0 (by rw [hrs]; positivity)]
  · rw [if_neg (by simpa using hi0), hroots (roots.size - i) (by omega), inv_pow]
    apply eq_inv_of_mul_eq_one_left
    rw [← pow_add, Nat.sub_add_cancel (Nat.le_of_lt hi'), hrs]
    exact hω.pow_eq_one

theorem blob_roots_valid :
    RootsValid (Kzg.Model.roots 12) ∧
      RootsValid (Kzg.Model.inverseRoots (Kzg.Model.roots 12)) := by
  have hroots : RootsValid (Kzg.Model.roots 12) := by
    refine ⟨domainRoot 4096, 12, ?_, domainRoot_4096_primitive, ?_⟩
    · exact size_computeRootsOfUnity _
    · intro i hi
      apply getElem!_computeRootsOfUnity_pow
      simpa [Kzg.Model.roots, size_computeRootsOfUnity] using hi
  exact ⟨hroots, inverse_roots_valid _ hroots⟩

end LeanBlsSimd.Kzg.Extender.Kernel
