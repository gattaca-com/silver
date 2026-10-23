import LeanBlsSimd.Refines.G1
import LeanBlsSimd.Refines.WrapperLengths
import LeanBlsSimd.Proofs.G1

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.UncompressG1

open DecompressG1

theorem specVerdict_some_iff (bytes : Array U8 48#usize) (p : blst.blst_p1_affine) :
    specVerdict bytes = some p ↔
      (EthLib.Cryptography.Kzg.bytesToKzgProof (G1Spec.toBytes (ofArray ofU8 bytes))).isOk = true ∧
      ∃ P, EthLib.Cryptography.Bls.G1.uncompress (G1Spec.toBytes (ofArray ofU8 bytes)) = .ok P ∧
        p = toBlstP1Affine (G1Spec.blstLimbs P) := by
  rw [specVerdict, Option.map_eq_some_iff]
  constructor
  · rintro ⟨q, hq, rfl⟩
    obtain ⟨hk, P, hP, rfl⟩ := (G1Spec.verdict_some_iff _ q).mp hq
    exact ⟨hk, P, hP, rfl⟩
  · rintro ⟨hk, P, hP, rfl⟩
    exact ⟨G1Spec.blstLimbs P, (G1Spec.verdict_some_iff _ _).mpr ⟨hk, P, hP, rfl⟩, rfl⟩

def usesKernelAt [RuntimeFeatures] (inputs : Slice (Array U8 48#usize)) (i : ℕ) : Bool :=
  usesKernel RuntimeFeatures.simdAvailable (inputs.val.map (ofArray ofU8)) i

theorem usesKernelAt_iff [RuntimeFeatures] (inputs : Slice (Array U8 48#usize)) (i : ℕ) :
    usesKernelAt inputs i = true ↔
      RuntimeFeatures.simdAvailable = true ∧ i < inputs.val.length / 8 * 8 ∧
      (decompress (chunkAt (inputs.val.map (ofArray ofU8)) i)).undecided.toNat.testBit
        (i % 8) = false := by
  simp [usesKernelAt, usesKernel, Bool.and_eq_true, and_assoc]

/-- All slots are overwritten. IFMA lanes use the proved kernel; portable calls
use the singleton and pair contracts. The declaration retains its public name. -/
theorem uncompress_in_g1_eq_spec_or_blst [RuntimeFeatures] (hdec : G1DecoderCorrect)
    (inputs : Slice (Array U8 48#usize)) (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g1 inputs out = ok result ∧
      result.val.length = inputs.val.length ∧
      ∀ i : Fin inputs.val.length,
        result.val[i.val]? = some
          (if usesKernelAt inputs i.val then specVerdict inputs.val[i.val]
           else specVerdict inputs.val[i.val]) := by
  obtain ⟨result, hr, hv⟩ := uncompress_refines hdec inputs out hlen
  refine ⟨result, hr, ?_, ?_⟩
  · rw [hv]
    simp
  · intro i
    rw [hv, List.getElem?_eq_getElem (by simp)]
    congr 1
    rw [List.getElem_map, getElem_uncompress _ _ _ _ (by simp)]
    by_cases hk : usesKernelAt inputs i.val = true
    · have hu := ((usesKernelAt_iff inputs i.val).mp hk).2.2
      have hc : (chunkAt (inputs.val.map (ofArray ofU8)) i.val)[i.val % 8] =
          ofArray ofU8 inputs.val[i.val] := by
        simp only [chunkAt, Vector.getElem_ofFn]
        rw [show i.val / 8 * 8 + i.val % 8 = i.val by omega, getElem!_pos _ _ (by simp), List.getElem_map]
      simp only [usesKernelAt] at hk
      rw [if_pos hk, decompress_eq_spec _ _ hu]
      simp only [Fin.getElem_fin, hc, specVerdict, usesKernelAt, hk, ↓reduceIte]
    · have hf : usesKernelAt inputs i.val = false := Bool.eq_false_iff.mpr hk
      simp only [usesKernelAt] at hf
      simp only [hf, Bool.false_eq_true, ↓reduceIte, usesKernelAt]
      rw [getElem!_pos _ _ (by simp), List.getElem_map]
      simp [modelBlst, toArray_ofArray, Option.map_map, Function.comp_def]

/-- Exact verdicts under the generated portable singleton and pair contracts. -/
theorem uncompress_in_g1_eq_spec [RuntimeFeatures]
    (hdec : G1DecoderCorrect)
    (inputs : Slice (Array U8 48#usize)) (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g1 inputs out = ok result ∧
      result.val.length = inputs.val.length ∧
      ∀ i : Fin inputs.val.length,
        result.val[i.val]? = some (specVerdict inputs.val[i.val]) := by
  obtain ⟨result, hr, hl, hv⟩ := uncompress_in_g1_eq_spec_or_blst hdec inputs out hlen
  refine ⟨result, hr, hl, ?_⟩
  intro i
  simpa only [ite_self] using hv i

/-- The list form transports directly across another extraction's copy of blst's structs. -/
theorem uncompress_in_g1_eq_spec_list [RuntimeFeatures] (hdec : G1DecoderCorrect)
    (inputs : Slice (Array U8 48#usize)) (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g1 inputs out = ok result ∧
      result.val = inputs.val.map specVerdict := by
  obtain ⟨result, hr, hl, hv⟩ := uncompress_in_g1_eq_spec hdec inputs out hlen
  refine ⟨result, hr, List.ext_getElem (by simpa using hl) ?_⟩
  intro i hi hj
  have hi' : i < inputs.val.length := by omega
  have h := hv ⟨i, hi'⟩
  simpa only [List.getElem?_eq_getElem hi, Option.some.injEq, List.getElem_map] using h

theorem uncompress_in_g1_eq_spec_model_list [RuntimeFeatures] (hdec : G1DecoderCorrect)
    (inputs : Slice (Array U8 48#usize)) (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g1 inputs out = ok result ∧
      result.val.map (Option.map ofBlstP1Affine) =
        inputs.val.map (G1Spec.verdict ∘ ofArray ofU8) := by
  obtain ⟨result, hr, hv⟩ := uncompress_in_g1_eq_spec_list hdec inputs out hlen
  refine ⟨result, hr, ?_⟩
  simp [hv, specVerdict, List.map_map, Option.map_map, Function.comp_def]

end LeanBlsSimd.UncompressG1
