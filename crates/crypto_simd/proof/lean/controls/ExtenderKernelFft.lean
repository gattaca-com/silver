import LeanBlsSimd.Kzg.Extender.Kernel.Fft
import LeanBlsSimd.Kzg.SpecExternals

open Aeneas Aeneas.Std Result
open EthCryptographySpecs Bls Kzg Kzg.BitReversal
open scoped EthCryptographySpecs.Bls.Fr BigOperators
open silver_crypto_simd silver_crypto_simd.kzg

attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero

namespace LeanBlsSimd.Kzg.Extender.Controls.KernelFft

open Kernel

set_option maxHeartbeats 2000000
set_option exponentiation.threshold 1000

/-- Indexed values distinguish table positions without assuming a Fourier root law. -/
def layoutRoots : _root_.Array Fr := _root_.Array.ofFn (fun i : Fin 32 => Fr.ofNat i.val)

private theorem layoutRoots_size : layoutRoots.size = 32 := _root_.Array.size_ofFn

private theorem layoutRoots_get (i : Nat) (hi : i < 32) : layoutRoots[i]! = Fr.ofNat i := by
  rw [getElem!_pos layoutRoots i (by rw [layoutRoots_size]; exact hi)]
  simp only [layoutRoots, _root_.Array.getElem_ofFn]

private theorem sampled_layout : sampleRoots layoutRoots 32 = layoutRoots := by
  apply _root_.Array.ext
  · simp only [sampleRoots, _root_.Array.size_ofFn, layoutRoots_size]
  · intro i hi hj
    simp only [sampleRoots, _root_.Array.getElem_ofFn, layoutRoots_size,
      show 32/32 = 1 by decide, Nat.mul_one]
    exact getElem!_pos layoutRoots i hj

def layoutInput : Slice blst.blst_fr :=
  ⟨layoutRoots.toList.map frEncode, by
    simp only [List.length_map, _root_.Array.length_toList, layoutRoots_size]
    scalar_tac⟩

private theorem layout_table_exists :
    ∃ table, @fft8.Fft8.new specExternals layoutInput 32#usize = ok table ∧
      FftInvariant table layoutRoots := by
  obtain ⟨table, hnew, ht⟩ := @fft_new_refinement specExternals specExternals_correct.1
    layoutInput layoutRoots 32#usize ⟨5, by decide, by decide, rfl⟩
    (by rw [layoutRoots_size]; decide) (by rw [layoutRoots_size]; decide) rfl
  exact ⟨table, hnew, by simpa only [UScalar.ofNatCore_val_eq, sampled_layout] using ht⟩

def swapSmallTwiddles (table : fft8.Fft8) : fft8.Fft8 :=
  { table with stage2 := table.stage4, stage4 := table.stage2 }

theorem swapped_stage2_stage4_violates_generated_table :
    ∃ table, @fft8.Fft8.new specExternals layoutInput 32#usize = ok table ∧
      FftInvariant table layoutRoots ∧ ¬ FftInvariant (swapSmallTwiddles table) layoutRoots := by
  obtain ⟨table, hnew, ht⟩ := layout_table_exists
  refine ⟨table, hnew, ht, ?_⟩
  intro hmut
  have hgood := ht.2.2.2.2.2.2 ⟨1, by decide⟩
  have hbad := hmut.2.2.2.2.1.2 ⟨1, by decide⟩
  change laneValue table.stage4 ⟨1, by decide⟩ = _ at hbad
  have he := hgood.symm.trans hbad
  simp only [layoutRoots_size] at he
  change layoutRoots[4]! * Fr.ofNat (2^260) = layoutRoots[8]! * Fr.ofNat (2^260) at he
  rw [layoutRoots_get 4 (by decide), layoutRoots_get 8 (by decide)] at he
  exact (by decide +kernel : Fr.ofNat 4 * Fr.ofNat (2^260) ≠ Fr.ofNat 8 * Fr.ofNat (2^260)) he

def readNextWideVector (table : fft8.Fft8) : fft8.Fft8 :=
  { table with wide := alloc.vec.Vec.set table.wide 0#usize table.wide.val[1]! }

theorem reading_next_wide_vector_violates_generated_table :
    ∃ table, @fft8.Fft8.new specExternals layoutInput 32#usize = ok table ∧
      FftInvariant table layoutRoots ∧ ¬ FftInvariant (readNextWideVector table) layoutRoots := by
  obtain ⟨table, hnew, ht⟩ := layout_table_exists
  refine ⟨table, hnew, ht, ?_⟩
  intro hmut
  have hlen : table.wide.val.length = 3 := by
    simpa only [layoutRoots_size] using ht.2.2.1
  have hset : (readNextWideVector table).wide.val[0]! = table.wide.val[1]! := by
    change (table.wide.val.set 0 table.wide.val[1]!)[0]! = _
    exact List.getElem!_set _ _ _ (by omega)
  have hgood := (ht.2.2.2.1 4 (by decide) (by rw [layoutRoots_size]; decide)
    ⟨0, by decide⟩).2 ⟨1, by decide⟩
  have hbad := (hmut.2.2.2.1 3 (by decide) (by rw [layoutRoots_size]; decide)
    ⟨0, by decide⟩).2 ⟨1, by decide⟩
  change laneValue (readNextWideVector table).wide.val[0]! ⟨1, by decide⟩ = _ at hbad
  rw [hset] at hbad
  have he := hgood.symm.trans hbad
  simp only [layoutRoots_size] at he
  change layoutRoots[1]! * Fr.ofNat (2^260) = layoutRoots[2]! * Fr.ofNat (2^260) at he
  rw [layoutRoots_get 1 (by decide), layoutRoots_get 2 (by decide)] at he
  exact (by decide +kernel : Fr.ofNat 1 * Fr.ofNat (2^260) ≠ Fr.ofNat 2 * Fr.ofNat (2^260)) he

def swapScatter (pairs : fft8.LanePairs) : fft8.LanePairs :=
  { pairs with first := pairs.second, second := pairs.first }

theorem swapped_scatter_does_not_restore_input :
    ∃ pairs, fft8.LanePairs.new 1#usize = ok pairs ∧ LanePairsInvariant pairs 1 ∧
      let a : M512 := .replicate 8 0
      let b : M512 := .replicate 8 1
      let upper := _mm512_permutex2var_epi64 a pairs.upper b
      let lower := _mm512_permutex2var_epi64 a pairs.lower b
      _mm512_permutex2var_epi64 upper (swapScatter pairs).first lower ≠ a := by
  obtain ⟨pairs, hnew, hp⟩ := lane_pairs_refinement 1#usize (by simp)
  refine ⟨pairs, hnew, hp, ?_⟩
  have h := (gather_scatter_inverse pairs 1 hp (.replicate 8 0) (.replicate 8 1)).2
  dsimp only
  rw [show (swapScatter pairs).first = pairs.second from rfl, h]
  decide

def impulse (atIndex : Nat) : _root_.Array Fr :=
  _root_.Array.ofFn (fun i : Fin 16 => if i.val = atIndex then 1 else 0)

private theorem impulse_size (atIndex : Nat) : (impulse atIndex).size = 16 := _root_.Array.size_ofFn

private theorem impulse_get (atIndex i : Nat) (hi : i < 16) :
    (impulse atIndex)[i]! = if i = atIndex then 1 else 0 := by
  rw [getElem!_pos (impulse atIndex) i (by rw [impulse_size]; exact hi)]
  simp only [impulse, _root_.Array.getElem_ofFn]

private theorem reversed_impulse : bitReversalPermutation (impulse 1) = impulse 8 := by
  decide +kernel

private theorem impulse_fft_get (roots : _root_.Array Fr) (ω : Fr)
    (hsize : roots.size = 16) (hω : IsPrimitiveRoot ω 16)
    (hroots : ∀ i, i < 16 → roots[i]! = ω^i)
    (t j : Nat) (ht : t < 16) (hj : j < 16) :
    (fftFieldAux (impulse t) roots)[j]! = ω^(t*j) := by
  rw [getElem!_fftFieldAux_dft (k := 4) hω (impulse t) roots (impulse_size t) hsize hroots j hj]
  trans ∑ i ∈ Finset.range 16, (if i = t then (1 : Fr) else 0) * ω^(i*j)
  · apply Finset.sum_congr rfl
    intro i hi
    rw [impulse_get t i (Finset.mem_range.mp hi)]
  · simp only [ite_mul, zero_mul, Finset.sum_ite_eq', Finset.mem_range, ht, if_true]
    exact one_mul _

private theorem dit_ne_dif (roots : _root_.Array Fr) (hsize : roots.size = 16)
    (hroots : RootsValid roots) :
    iterativeDit 4 (impulse 1) roots ≠ iterativeDif 4 (impulse 1) roots := by
  obtain ⟨ω, k, hs, hω, hpowers⟩ := hroots
  have hk : k = 4 := Nat.pow_right_injective (by decide : 1 < 2) (hs.symm.trans hsize)
  subst k
  have hv : RootsValid roots := ⟨ω, 4, hs, hω, hpowers⟩
  intro he
  rw [iterative_dit_eq_spec_pow _ _ 4 ((impulse_size 1).trans hsize.symm) hs hv,
    iterative_dif_eq_spec_pow _ _ 4 ((impulse_size 1).trans hsize.symm) hs hv,
    reversed_impulse] at he
  have hi := congrArg (fun xs : _root_.Array Fr => xs[2]!) he
  dsimp only at hi
  rw [impulse_fft_get roots ω hsize hω (by simpa only [hsize] using hpowers) 8 2
      (by decide) (by decide),
    getElem!_pos (bitReversalPermutation (fftFieldAux (impulse 1) roots)) 2
      (by simp only [size_bitReversalPermutation, size_fftFieldAux, impulse_size]; decide),
    getElem_bitReversalPermutation, size_fftFieldAux, impulse_size,
    show reverseBits 2 16 = 4 by decide +kernel,
    impulse_fft_get roots ω hsize hω (by simpa only [hsize] using hpowers) 1 4
      (by decide) (by decide)] at hi
  change ω^(16 : Nat) = ω^(4 : Nat) at hi
  have hp : ω^(16 : Nat) = 1 := hω.pow_eq_one
  rw [hp] at hi
  exact hω.pow_ne_one_of_pos_of_lt (by decide : 4 ≠ 0) (by decide : 4 < 16) hi.symm

def roots16 : _root_.Array Fr := computeRootsOfUnity 16

private theorem roots16_size : roots16.size = 16 := size_computeRootsOfUnity 16

private theorem roots16_valid : RootsValid roots16 := by
  refine ⟨domainRoot 16, 4, roots16_size,
    isPrimitiveRoot_domainRoot (Nat.dvd_of_mod_eq_zero (by decide)), ?_⟩
  intro i hi
  exact getElem!_computeRootsOfUnity_pow 16 i (by simpa only [roots16_size] using hi)

/-- Both replacements disagree on a valid 16-point domain; index 2 separates them. -/
theorem replacing_inverse_dit_and_forward_dif_changes_results :
    iterativeDif 4 (impulse 1) (Kzg.Model.inverseRoots roots16) ≠
      iterativeDit 4 (impulse 1) (Kzg.Model.inverseRoots roots16) ∧
    iterativeDit 4 (impulse 1) roots16 ≠ iterativeDif 4 (impulse 1) roots16 := by
  exact ⟨Ne.symm (dit_ne_dif _ (by simp only [Kzg.Model.inverseRoots, _root_.Array.size_ofFn, roots16_size])
    (inverse_roots_valid roots16 roots16_valid)), dit_ne_dif roots16 roots16_size roots16_valid⟩

end LeanBlsSimd.Kzg.Extender.Controls.KernelFft

#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelFft.swapped_stage2_stage4_violates_generated_table
#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelFft.reading_next_wide_vector_violates_generated_table
#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelFft.swapped_scatter_does_not_restore_input
#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelFft.replacing_inverse_dit_and_forward_dif_changes_results
