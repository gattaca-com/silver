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
def layoutRoots : _root_.Array Fr := _root_.Array.ofFn (fun i : Fin 64 => Fr.ofNat i.val)

private theorem layoutRoots_size : layoutRoots.size = 64 := _root_.Array.size_ofFn

private theorem layoutRoots_get (i : Nat) (hi : i < 64) : layoutRoots[i]! = Fr.ofNat i := by
  rw [getElem!_pos layoutRoots i (by rw [layoutRoots_size]; exact hi)]
  simp only [layoutRoots, _root_.Array.getElem_ofFn]

private theorem sampled_layout : sampleRoots layoutRoots 64 = layoutRoots := by
  apply _root_.Array.ext
  · simp only [sampleRoots, _root_.Array.size_ofFn, layoutRoots_size]
  · intro i hi hj
    simp only [sampleRoots, _root_.Array.getElem_ofFn, layoutRoots_size,
      show 64/64 = 1 by decide, Nat.mul_one]
    exact getElem!_pos layoutRoots i hj

def layoutInput : Slice blst.blst_fr :=
  ⟨layoutRoots.toList.map frEncode, by
    simp only [List.length_map, _root_.Array.length_toList, layoutRoots_size]
    scalar_tac⟩

private theorem layout_table_exists :
    ∃ table, @fft8.Fft8.new specExternals layoutInput 64#usize = ok table ∧
      FftInvariant table layoutRoots := by
  obtain ⟨table, hnew, ht⟩ := @fft_new_refinement specExternals specExternals_correct.1
    layoutInput layoutRoots 64#usize ⟨6, by decide, by decide, rfl⟩
    (by rw [layoutRoots_size]; decide) (by rw [layoutRoots_size]; decide) rfl
  exact ⟨table, hnew, by simpa only [UScalar.ofNatCore_val_eq, sampled_layout] using ht⟩

def swapShortTwiddles (table : fft8.Fft8) : fft8.Fft8 :=
  { table with
    short := alloc.vec.Vec.set
      (alloc.vec.Vec.set table.short 2#usize table.short.val[4]!)
      4#usize table.short.val[2]! }

theorem swapped_short_twiddles_violates_generated_table :
    ∃ table, @fft8.Fft8.new specExternals layoutInput 64#usize = ok table ∧
      FftInvariant table layoutRoots ∧ ¬ FftInvariant (swapShortTwiddles table) layoutRoots := by
  obtain ⟨table, hnew, ht⟩ := layout_table_exists
  refine ⟨table, hnew, ht, ?_⟩
  intro hmut
  have hlen : table.short.val.length = 7 := ht.2.2.2.2.1
  have hset : (swapShortTwiddles table).short.val[2]! = table.short.val[4]! := by
    change ((table.short.val.set 2 table.short.val[4]!).set 4 table.short.val[2]!)[2]! = _
    rw [List.getElem!_set_ne _ 4 2 _ (by decide), List.getElem!_set _ _ _ (by omega)]
  have hgood := (ht.2.2.2.2.2 4 (by simp) ⟨1, by decide⟩).1.2 ⟨0, by decide⟩
  have hbad := (hmut.2.2.2.2.2 2 (by simp) ⟨1, by decide⟩).1.2 ⟨0, by decide⟩
  change laneValue (swapShortTwiddles table).short.val[2]! ⟨0, by decide⟩ = _ at hbad
  rw [hset] at hbad
  have he := hgood.symm.trans hbad
  simp only [layoutRoots_size] at he
  change layoutRoots[8]! * Fr.ofNat (2^260) = layoutRoots[16]! * Fr.ofNat (2^260) at he
  rw [layoutRoots_get 8 (by decide), layoutRoots_get 16 (by decide)] at he
  exact (by decide +kernel : Fr.ofNat 8 * Fr.ofNat (2^260) ≠ Fr.ofNat 16 * Fr.ofNat (2^260)) he

def readNextWideVector (table : fft8.Fft8) : fft8.Fft8 :=
  { table with wide := alloc.vec.Vec.set table.wide 0#usize table.wide.val[1]! }

theorem reading_next_wide_vector_violates_generated_table :
    ∃ table, @fft8.Fft8.new specExternals layoutInput 64#usize = ok table ∧
      FftInvariant table layoutRoots ∧ ¬ FftInvariant (readNextWideVector table) layoutRoots := by
  obtain ⟨table, hnew, ht⟩ := layout_table_exists
  refine ⟨table, hnew, ht, ?_⟩
  intro hmut
  have hlen : table.wide.val.length = 7 := by
    simpa only [layoutRoots_size] using ht.2.2.1
  have hset : (readNextWideVector table).wide.val[0]! = table.wide.val[1]! := by
    change (table.wide.val.set 0 table.wide.val[1]!)[0]! = _
    exact List.getElem!_set _ _ _ (by omega)
  have hgood := (ht.2.2.2.1 4 (by decide) (by rw [layoutRoots_size]; decide)
    ⟨0, by decide⟩).1.2 ⟨1, by decide⟩
  have hbad := (hmut.2.2.2.1 3 (by decide) (by rw [layoutRoots_size]; decide)
    ⟨0, by decide⟩).1.2 ⟨1, by decide⟩
  change laneValue (readNextWideVector table).wide.val[0]! ⟨1, by decide⟩ = _ at hbad
  rw [hset] at hbad
  have he := hgood.symm.trans hbad
  simp only [layoutRoots_size] at he
  change layoutRoots[2]! * Fr.ofNat (2^260) = layoutRoots[4]! * Fr.ofNat (2^260) at he
  rw [layoutRoots_get 2 (by decide), layoutRoots_get 4 (by decide)] at he
  exact (by decide +kernel : Fr.ofNat 2 * Fr.ofNat (2^260) ≠ Fr.ofNat 4 * Fr.ofNat (2^260)) he

/-- The scalar layout of one transposed 8×8 block. -/
def transposeValues (values : _root_.Array Fr) : _root_.Array Fr :=
  _root_.Array.ofFn (fun i : Fin 64 => values[(i.val % 8)*8+i.val/8]!)

def shortImpulse (atIndex : Nat) : _root_.Array Fr :=
  _root_.Array.ofFn (fun i : Fin 64 => if i.val = atIndex then 1 else 0)

def unitRoots : _root_.Array Fr := _root_.Array.replicate 64 1

def indexedUnitRoots : _root_.Array Fr :=
  _root_.Array.ofFn (fun i : Fin 64 => if i.val = 0 then 1 else Fr.ofNat i.val)

example : TransformSize unitRoots.size ∧ unitRoots[0]! = 1 ∧
    TransformSize indexedUnitRoots.size ∧ indexedUnitRoots[0]! = 1 ∧
    (shortImpulse 1).size = 64 ∧ (shortImpulse 3).size = 64 := by
  exact ⟨⟨6, by decide, by decide, rfl⟩, by decide +kernel,
    ⟨6, by decide, by decide, rfl⟩, by decide +kernel, rfl, rfl⟩

/- `short_refinement` identifies these stage values with the generated short calls.
Skipping j = 0 is valid because roots[0] = 1; skipping j = 1 changes this product. -/
theorem skipped_nonunit_product_changes_short_stage :
    (butterflyStage true (shortImpulse 3) indexedUnitRoots 2)[1]! ≠
      (butterflyStage true (shortImpulse 3) unitRoots 2)[1]! := by
  decide +kernel

/- `block_run_representation` composes both generated transposes with the three
short stages. Omitting the input transpose applies the stages to transposed values;
omitting the output transpose leaves their result transposed. These are semantic
controls on that composition, with roots satisfying its unit-root premise. -/
theorem missing_input_transpose_changes_block :
    (shortStages true (transposeValues (shortImpulse 1)) unitRoots)[0]! ≠
      (shortStages true (shortImpulse 1) unitRoots)[0]! := by
  decide +kernel

theorem missing_output_transpose_changes_block :
    (transposeValues (shortStages true (shortImpulse 1) unitRoots))[1]! ≠
      (shortStages true (shortImpulse 1) unitRoots)[1]! := by
  decide +kernel

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

#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelFft.swapped_short_twiddles_violates_generated_table
#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelFft.reading_next_wide_vector_violates_generated_table
#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelFft.replacing_inverse_dit_and_forward_dif_changes_results

#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelFft.skipped_nonunit_product_changes_short_stage
#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelFft.missing_input_transpose_changes_block
#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelFft.missing_output_transpose_changes_block
