import LeanBlsSimd.Refines.G1
import LeanBlsSimd.Proofs.G1

open Aeneas Aeneas.Std Result
open silver_bls_simd

namespace LeanBlsSimd.UncompressG1

open DecompressG1

def specVerdict (bytes : Array U8 48#usize) : Option blst.blst_p1_affine :=
  (G1Spec.verdict (ofArray ofU8 bytes)).map toBlstP1Affine

/-- The scalar external returns the KZG verdict, including the exact affine limbs. -/
def BlstMatchesSpec [G1Externals] : Prop :=
  ∀ bytes : Array U8 48#usize, G1Externals.uncompress bytes = specVerdict bytes

theorem specVerdict_some_iff (bytes : Array U8 48#usize) (p : blst.blst_p1_affine) :
    specVerdict bytes = some p ↔
      (EthCryptographySpecs.Kzg.bytesToKzgProof (G1Spec.toBytes (ofArray ofU8 bytes))).isOk = true ∧
      ∃ P, EthCryptographySpecs.Bls.G1.uncompress (G1Spec.toBytes (ofArray ofU8 bytes)) = .ok P ∧
        p = toBlstP1Affine (G1Spec.blstLimbs P) := by
  rw [specVerdict, Option.map_eq_some_iff]
  constructor
  · rintro ⟨q, hq, rfl⟩
    obtain ⟨hk, P, hP, rfl⟩ := (G1Spec.verdict_some_iff _ q).mp hq
    exact ⟨hk, P, hP, rfl⟩
  · rintro ⟨hk, P, hP, rfl⟩
    exact ⟨G1Spec.blstLimbs P, (G1Spec.verdict_some_iff _ _).mpr ⟨hk, P, hP, rfl⟩, rfl⟩

def usesKernelAt [G1Externals] (inputs : Slice (Array U8 48#usize)) (i : ℕ) : Bool :=
  usesKernel G1Externals.simdAvailable (inputs.val.map (ofArray ofU8)) i

theorem usesKernelAt_iff [G1Externals] (inputs : Slice (Array U8 48#usize)) (i : ℕ) :
    usesKernelAt inputs i = true ↔
      G1Externals.simdAvailable = true ∧ i < inputs.val.length / 8 * 8 ∧
      (decompress (chunkAt (inputs.val.map (ofArray ofU8)) i)).undecided.toNat.testBit
        (i % 8) = false := by
  simp [usesKernelAt, usesKernel, Bool.and_eq_true, and_assoc]

/-- All slots are overwritten. The route is determined by SIMD, chunk size, and the
kernel's actual undecided mask; the scalar external is otherwise unconstrained. -/
theorem uncompress_in_g1_eq_spec_or_blst [G1Externals]
    (inputs : Slice (Array U8 48#usize)) (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_bls_simd.uncompress_in_g1 inputs out = ok result ∧
      result.val.length = inputs.val.length ∧
      ∀ i : Fin inputs.val.length,
        result.val[i.val]? = some
          (if usesKernelAt inputs i.val then specVerdict inputs.val[i.val]
           else G1Externals.uncompress inputs.val[i.val]) := by
  obtain ⟨result, hr, hv⟩ := uncompress_refines inputs out hlen
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

/-- The sole extra premise relates the total blst external to the KZG verdict on all
48-byte inputs. No completeness, decided-lane, or CPU premise is required. -/
theorem uncompress_in_g1_eq_spec [G1Externals]
    (hblst : ∀ bytes : Array U8 48#usize, G1Externals.uncompress bytes = specVerdict bytes)
    (inputs : Slice (Array U8 48#usize)) (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_bls_simd.uncompress_in_g1 inputs out = ok result ∧
      result.val.length = inputs.val.length ∧
      ∀ i : Fin inputs.val.length,
        result.val[i.val]? = some (specVerdict inputs.val[i.val]) := by
  obtain ⟨result, hr, hl, hv⟩ := uncompress_in_g1_eq_spec_or_blst inputs out hlen
  refine ⟨result, hr, hl, ?_⟩
  intro i
  simpa only [hblst, ite_self] using hv i

/-- The list form transports directly across another extraction's copy of blst's structs. -/
theorem uncompress_in_g1_eq_spec_list [G1Externals] (hblst : BlstMatchesSpec)
    (inputs : Slice (Array U8 48#usize)) (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_bls_simd.uncompress_in_g1 inputs out = ok result ∧
      result.val = inputs.val.map specVerdict := by
  obtain ⟨result, hr, hl, hv⟩ := uncompress_in_g1_eq_spec hblst inputs out hlen
  refine ⟨result, hr, List.ext_getElem (by simpa using hl) ?_⟩
  intro i hi hj
  have hi' : i < inputs.val.length := by omega
  have h := hv ⟨i, hi'⟩
  simpa only [List.getElem?_eq_getElem hi, Option.some.injEq, List.getElem_map] using h

theorem uncompress_in_g1_eq_spec_model_list [G1Externals] (hblst : BlstMatchesSpec)
    (inputs : Slice (Array U8 48#usize)) (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_bls_simd.uncompress_in_g1 inputs out = ok result ∧
      result.val.map (Option.map ofBlstP1Affine) =
        inputs.val.map (G1Spec.verdict ∘ ofArray ofU8) := by
  obtain ⟨result, hr, hv⟩ := uncompress_in_g1_eq_spec_list hblst inputs out hlen
  refine ⟨result, hr, ?_⟩
  simp [hv, specVerdict, List.map_map, Option.map_map, Function.comp_def]

end LeanBlsSimd.UncompressG1
