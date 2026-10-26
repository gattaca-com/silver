import LeanBlsSimd.Kzg.PointValidity
import LeanBlsSimd.Refines.Complete
import LeanBlsSimd.Refines.WrapperLengths
import LeanBlsSimd.Refines.G2Wrapper
import LeanBlsSimd.Proofs.UncompressG2

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.UncompressG2

open DecompressG2

def specVerdict (bytes : Array U8 96#usize) : Option g2_point.G2Point :=
  (G2Spec.verdict (ofArray ofU8 bytes)).map toBlstP2Affine

/-- Agreement includes acceptance and every affine limb, including infinity's zero limbs. -/
def BlstMatchesSpec [BlsExternals] : Prop :=
  ∀ bytes : Array U8 96#usize, BlsExternals.uncompressG2 bytes = specVerdict bytes

theorem specVerdict_valid (bytes : Array U8 96#usize) (p : g2_point.G2Point)
    (h : specVerdict bytes = some p) : Kzg.G2AffineValid p := by
  obtain ⟨q, hq, rfl⟩ := Option.map_eq_some_iff.mp h
  exact Kzg.g2_verdict_valid _ q hq

theorem specVerdict_some_iff (bytes : Array U8 96#usize) (p : g2_point.G2Point) :
    specVerdict bytes = some p ↔
      ∃ P, EthLib.Cryptography.Bls.G2.uncompress (toBytes (ofArray ofU8 bytes)) = .ok P ∧
        EthLib.Cryptography.Bls.G2.inSubgroup P = true ∧
        p = toBlstP2Affine (G2Spec.blstLimbs P) := by
  rw [specVerdict, Option.map_eq_some_iff]
  constructor
  · rintro ⟨q, hq, rfl⟩
    obtain ⟨P, hP, hg, rfl⟩ := (G2Spec.verdict_some_iff _ q).mp hq
    exact ⟨P, hP, hg, rfl⟩
  · rintro ⟨P, hP, hg, rfl⟩
    exact ⟨G2Spec.blstLimbs P, (G2Spec.verdict_some_iff _ _).mpr ⟨P, hP, hg, rfl⟩, rfl⟩

def usesKernelAt [RuntimeFeatures] (inputs : Slice (Array U8 96#usize)) (i : ℕ) : Bool :=
  usesKernel RuntimeFeatures.simdAvailable (inputs.val.map (ofArray ofU8)) i

theorem usesKernelAt_iff [RuntimeFeatures] (inputs : Slice (Array U8 96#usize)) (i : ℕ) :
    usesKernelAt inputs i = true ↔
      RuntimeFeatures.simdAvailable = true ∧ i < inputs.val.length ∧
      3 ≤ min 8 (inputs.val.length - i / 8 * 8) ∧
      (decompress (chunkAt (inputs.val.map (ofArray ofU8)) i)).undecided.toNat.testBit
        (i % 8) = false := by
  simp [usesKernelAt, usesKernel, chunkLength, Bool.and_eq_true, and_assoc]

/-- Every slot is overwritten. Decided kernel lanes use the specification; all other
lanes preserve the arbitrary scalar external's result. -/
theorem uncompress_in_g2_eq_spec_or_blst [RuntimeFeatures] [BlsExternals]
    (inputs : Slice (Array U8 96#usize)) (out : Slice (Option g2_point.G2Point))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g2 inputs out = ok result ∧
      result.val.length = inputs.val.length ∧
      ∀ i : Fin inputs.val.length,
        result.val[i.val]? = some
          (if usesKernelAt inputs i.val then specVerdict inputs.val[i.val]
           else BlsExternals.uncompressG2 inputs.val[i.val]) := by
  obtain ⟨result, hr, hv⟩ := uncompress_refines inputs out hlen
  refine ⟨result, hr, ?_, ?_⟩
  · rw [hv]
    simp
  · intro i
    rw [hv, List.getElem?_eq_getElem (by simp)]
    congr 1
    rw [List.getElem_map, getElem_uncompress _ _ _ _ (by simp)]
    by_cases hk : usesKernelAt inputs i.val = true
    · have hu := ((usesKernelAt_iff inputs i.val).mp hk).2.2.2
      have hc : (chunkAt (inputs.val.map (ofArray ofU8)) i.val)[i.val % 8] =
          ofArray ofU8 inputs.val[i.val] := by
        have hmin : min (i.val % 8) (chunkLength (inputs.val.map (ofArray ofU8)) i.val - 1) = i.val % 8 := by
          simp only [chunkLength, List.length_map]
          omega
        simp only [chunkAt, Vector.getElem_ofFn, hmin]
        rw [show i.val / 8 * 8 + i.val % 8 = i.val by omega,
          getElem!_pos _ _ (by simp), List.getElem_map]
      simp only [usesKernelAt] at hk
      rw [if_pos hk]
      simp only [getElem!_pos (decompress (chunkAt (inputs.val.map (ofArray ofU8)) i.val)).points
        (i.val % 8) (Nat.mod_lt i.val (by decide : 0 < 8))]
      have he := decompress_eq_verdict _ ⟨i.val % 8, Nat.mod_lt _ (by decide)⟩ hu
      simp only [Fin.getElem_fin] at he
      rw [he]
      simp only [hc, specVerdict, usesKernelAt, hk, ↓reduceIte]
    · have hf : usesKernelAt inputs i.val = false := Bool.eq_false_iff.mpr hk
      simp only [usesKernelAt] at hf
      simp only [hf, Bool.false_eq_true, ↓reduceIte, usesKernelAt]
      rw [getElem!_pos _ _ (by simp), List.getElem_map]
      exact modelBlst_roundtrip inputs.val[i.val]

theorem uncompress_in_g2_eq_blst [RuntimeFeatures] [BlsExternals] (hblst : BlstMatchesSpec)
    (inputs : Slice (Array U8 96#usize)) (out : Slice (Option g2_point.G2Point))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g2 inputs out = ok result ∧
      result.val = inputs.val.map BlsExternals.uncompressG2 := by
  obtain ⟨result, hr, hl, hv⟩ := uncompress_in_g2_eq_spec_or_blst inputs out hlen
  refine ⟨result, hr, List.ext_getElem (by simpa using hl) ?_⟩
  intro i hi hj
  have hi' : i < inputs.val.length := by omega
  have hs : ∀ bytes, specVerdict bytes = BlsExternals.uncompressG2 bytes := fun bytes => (hblst bytes).symm
  have h := hv ⟨i, hi'⟩
  simpa only [hs, ite_self, List.getElem?_eq_getElem hi, Option.some.injEq, List.getElem_map] using h

theorem uncompress_in_g2_eq_spec [RuntimeFeatures] [BlsExternals] (hblst : BlstMatchesSpec)
    (inputs : Slice (Array U8 96#usize)) (out : Slice (Option g2_point.G2Point))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g2 inputs out = ok result ∧
      result.val.length = inputs.val.length ∧
      ∀ i : Fin inputs.val.length,
        result.val[i.val]? = some (specVerdict inputs.val[i.val]) := by
  obtain ⟨result, hr, hl, hv⟩ := uncompress_in_g2_eq_spec_or_blst inputs out hlen
  refine ⟨result, hr, hl, ?_⟩
  intro i
  simpa only [hblst inputs.val[i.val], ite_self] using hv i

theorem uncompress_in_g2_eq_spec_list [RuntimeFeatures] [BlsExternals] (hblst : BlstMatchesSpec)
    (inputs : Slice (Array U8 96#usize)) (out : Slice (Option g2_point.G2Point))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g2 inputs out = ok result ∧
      result.val = inputs.val.map specVerdict ∧
      ∀ p, some p ∈ result.val → Kzg.G2AffineValid p := by
  obtain ⟨result, hr, hl, hv⟩ := uncompress_in_g2_eq_spec hblst inputs out hlen
  have heq : result.val = inputs.val.map specVerdict := by
    apply List.ext_getElem (by simpa using hl)
    intro i hi hj
    have hi' : i < inputs.val.length := by omega
    have h := hv ⟨i, hi'⟩
    simpa only [List.getElem?_eq_getElem hi, Option.some.injEq, List.getElem_map] using h
  refine ⟨result, hr, heq, ?_⟩
  intro p hp
  rw [heq] at hp
  obtain ⟨bytes, _, hb⟩ := List.mem_map.mp hp
  exact specVerdict_valid bytes p hb

theorem uncompress_in_g2_eq_spec_model_list [RuntimeFeatures] [BlsExternals] (hblst : BlstMatchesSpec)
    (inputs : Slice (Array U8 96#usize)) (out : Slice (Option g2_point.G2Point))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g2 inputs out = ok result ∧
      result.val.map (Option.map ofBlstP2Affine) =
        inputs.val.map (G2Spec.verdict ∘ ofArray ofU8) := by
  obtain ⟨result, hr, hv, _⟩ := uncompress_in_g2_eq_spec_list hblst inputs out hlen
  refine ⟨result, hr, ?_⟩
  simp [hv, specVerdict, List.map_map, Option.map_map, Function.comp_def]

end LeanBlsSimd.UncompressG2
