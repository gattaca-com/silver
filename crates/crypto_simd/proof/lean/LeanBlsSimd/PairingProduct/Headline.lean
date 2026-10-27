import LeanBlsSimd.PairingProduct.LaneSet

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.PairingProduct

noncomputable section

open ProductLoop

def build (pairs : List pairing_product.AffinePair) : Result pairing_product.PairingProduct := do
  let owner ← pairing_product.PairingProduct.Insts.CoreDefaultDefault.default
  pairs.foldlM (fun owner pair => pairing_product.PairingProduct.push owner pair.p pair.q) owner

theorem push_list_refines (pairs : List pairing_product.AffinePair)
    (valid : ∀ p ∈ pairs, Kzg.G1AffineValid p.p ∧ Kzg.G2AffineValid p.q)
    (owner : pairing_product.PairingProduct)
    (room : (owner.pairs.val ++ pairs.filter finitePair).length ≤ Usize.max) :
    ∃ result,
      pairs.foldlM (fun owner pair => pairing_product.PairingProduct.push owner pair.p pair.q) owner =
        ok result ∧ result.pairs.val = owner.pairs.val ++ pairs.filter finitePair := by
  induction pairs generalizing owner with
  | nil => exact ⟨owner, rfl, by simp⟩
  | cons pair pairs ih =>
    have hp := valid pair (by simp)
    have hroom : (owner.pairs.val ++ [⟨pair.p, pair.q⟩].filter finitePair).length ≤ Usize.max := by
      have he : (pair :: pairs).filter finitePair = [pair].filter finitePair ++ pairs.filter finitePair := by
        simp only [List.filter_cons, List.filter_nil]
        split <;> simp
      rw [he, ← List.append_assoc, List.length_append] at room
      change (owner.pairs.val ++ [pair].filter finitePair).length ≤ Usize.max
      omega
    obtain ⟨next, hpush, hnext⟩ := push_refines owner pair.p pair.q hp.1 hp.2 hroom
    have hnext' : next.pairs.val = owner.pairs.val ++ [pair].filter finitePair := by
      cases pair
      exact hnext
    obtain ⟨result, hloop, hresult⟩ := ih (fun p hp => valid p (by simp [hp])) next (by
      rw [hnext', List.append_assoc]
      simpa only [← List.filter_append, List.singleton_append] using room)
    refine ⟨result, ?_, ?_⟩
    · simp only [List.foldlM_cons, hpush, bind_tc_ok]
      exact hloop
    · rw [hresult, hnext', List.append_assoc, ← List.filter_append]
      rfl

theorem build_refines (pairs : List pairing_product.AffinePair)
    (valid : ∀ p ∈ pairs, Kzg.G1AffineValid p.p ∧ Kzg.G2AffineValid p.q)
    (room : (pairs.filter finitePair).length ≤ Usize.max) :
    ∃ owner, build pairs = ok owner ∧ owner.pairs.val = pairs.filter finitePair ∧
      (∀ p ∈ owner.pairs.val, Kzg.G1AffineValid p.p ∧ Kzg.G2AffineValid p.q) ∧
      (∀ p ∈ owner.pairs.val, finitePair p = true) := by
  obtain ⟨owner, hbuild, hval⟩ := push_list_refines pairs valid emptyOwner
    (by simpa only [emptyOwner_pairs, List.nil_append] using room)
  have he : owner.pairs.val = pairs.filter finitePair := by
    simpa only [emptyOwner_pairs, List.nil_append] using hval
  refine ⟨owner, ?_, he, ?_, ?_⟩
  · simpa only [build, default_empty, bind_tc_ok] using hbuild
  · intro p hp
    rw [he] at hp
    exact valid p (List.mem_filter.mp hp).1
  · intro p hp
    rw [he] at hp
    exact (List.mem_filter.mp hp).2

theorem factorProduct_filter (pairs : List pairing_product.AffinePair) :
    factorProduct (pairs.filter finitePair) = factorProduct pairs := by
  induction pairs with
  | nil => rfl
  | cons pair pairs ih =>
    by_cases hf : finitePair pair = true
    · simp only [List.filter_cons, hf, if_true, factorProduct, List.map_cons, List.prod_cons] at ih ⊢
      rw [ih]
    · have hi : ((Kzg.g1ReadAffine pair.p).isInfinity || (Kzg.g2ReadAffine pair.q).isInfinity) = true := by
        simpa only [finitePair, Bool.not_eq_true', Bool.not_eq_false] using hf
      simp only [List.filter_cons, hf, Bool.false_eq_true, if_false]
      rw [ih]
      simp only [factorProduct, List.map_cons, List.prod_cons, pairingFactor, hi, if_true,
        Fp12.toField_one, one_mul]

private theorem list_pairingCheck_eq (pairs : List pairing_product.AffinePair) :
    pairingCheck (pairs.map (fun p => (Kzg.g1ReadAffine p.p, Kzg.g2ReadAffine p.q))).toArray =
      decide (factorProduct pairs ^ finalExpExponent = 1) := by
  apply Bool.eq_iff_iff.mpr
  rw [SpecPairing.pairingCheck_eq, Fp12.isOne_iff, toField_finalExponentiation, toField_pairingFold]
  simp only [List.map_map, Function.comp_def, factorProduct, decide_eq_true_eq]

theorem check_correct [RuntimeFeatures] [PairingExternals]
    (blst : BlstMatchesSpec) (inputs : pairing_product.PairingInputs)
    (valid : ∀ p ∈ inputs.pairs.val, Kzg.G1AffineValid p.p ∧ Kzg.G2AffineValid p.q)
    (finite : ∀ p ∈ inputs.pairs.val, finitePair p = true) :
    pairing_product.PairingInputs.check inputs = ok (pairingCheck (specPairs inputs.pairs)) :=
  ProductLoop.check_refines single_set_correct blst inputs valid finite

theorem is_one_correct [RuntimeFeatures] [PairingExternals]
    (blst : BlstMatchesSpec) (owner : pairing_product.PairingProduct)
    (valid : ∀ p ∈ owner.pairs.val, Kzg.G1AffineValid p.p ∧ Kzg.G2AffineValid p.q)
    (finite : ∀ p ∈ owner.pairs.val, finitePair p = true) :
    pairing_product.PairingProduct.is_one owner =
      ok (pairingCheck (specPairs (alloc.vec.Vec.deref owner.pairs))) :=
  check_correct blst ⟨alloc.vec.Vec.deref owner.pairs⟩ valid finite

theorem two_pairs_are_one_correct [RuntimeFeatures] [PairingExternals]
    (blst : BlstMatchesSpec) (first second : g1_point.G1Point × g2_point.G2Point)
    (hp : Kzg.G1AffineValid first.1) (hq : Kzg.G2AffineValid first.2)
    (hp' : Kzg.G1AffineValid second.1) (hq' : Kzg.G2AffineValid second.2) :
    pairing_product.PairingProduct.two_pairs_are_one first second =
      ok (pairingCheck #[(Kzg.g1ReadAffine first.1, Kzg.g2ReadAffine first.2),
        (Kzg.g1ReadAffine second.1, Kzg.g2ReadAffine second.2)]) := by
  rw [two_pairs_filter first second hp hq hp' hq']
  have valid : ∀ p ∈ (filteredTwo ⟨first.1, first.2⟩ ⟨second.1, second.2⟩).val,
      Kzg.G1AffineValid p.p ∧ Kzg.G2AffineValid p.q := by
    intro p hm
    have h := (List.mem_filter.mp hm).1
    simp only [List.mem_cons, List.not_mem_nil, or_false] at h
    rcases h with rfl | rfl
    · exact ⟨hp, hq⟩
    · exact ⟨hp', hq'⟩
  have finite : ∀ p ∈ (filteredTwo ⟨first.1, first.2⟩ ⟨second.1, second.2⟩).val,
      finitePair p = true := fun _ hp => (List.mem_filter.mp hp).2
  rw [check_correct blst
    ⟨filteredTwo ⟨first.1, first.2⟩ ⟨second.1, second.2⟩⟩ valid finite, ProductLoop.pairingCheck_eq]
  have he := list_pairingCheck_eq [⟨first.1, first.2⟩, ⟨second.1, second.2⟩]
  simp only [List.map_cons, List.map_nil] at he
  rw [he]
  change ok (decide (factorProduct ([⟨first.1, first.2⟩, ⟨second.1, second.2⟩].filter finitePair) ^
    finalExpExponent = 1)) = _
  rw [factorProduct_filter]

theorem built_owner_correct [RuntimeFeatures] [PairingExternals]
    (blst : BlstMatchesSpec) (pairs : List pairing_product.AffinePair)
    (valid : ∀ p ∈ pairs, Kzg.G1AffineValid p.p ∧ Kzg.G2AffineValid p.q)
    (room : (pairs.filter finitePair).length ≤ Usize.max) :
    ∃ owner, build pairs = ok owner ∧ owner.pairs.val = pairs.filter finitePair ∧
      pairing_product.PairingProduct.is_one owner =
        ok (pairingCheck (pairs.map
          (fun p => (Kzg.g1ReadAffine p.p, Kzg.g2ReadAffine p.q))).toArray) := by
  obtain ⟨owner, hbuild, hval, hvalid, hfinite⟩ := build_refines pairs valid room
  refine ⟨owner, hbuild, hval, ?_⟩
  rw [is_one_correct blst owner hvalid hfinite, ProductLoop.pairingCheck_eq, list_pairingCheck_eq]
  change ok (decide (factorProduct owner.pairs.val ^ finalExpExponent = 1)) = _
  rw [hval, factorProduct_filter]

theorem build_is_one_correct [RuntimeFeatures] [PairingExternals]
    (blst : BlstMatchesSpec) (pairs : List pairing_product.AffinePair)
    (valid : ∀ p ∈ pairs, Kzg.G1AffineValid p.p ∧ Kzg.G2AffineValid p.q)
    (room : (pairs.filter finitePair).length ≤ Usize.max) :
    (do let owner ← build pairs; pairing_product.PairingProduct.is_one owner) =
      ok (pairingCheck (pairs.map
        (fun p => (Kzg.g1ReadAffine p.p, Kzg.g2ReadAffine p.q))).toArray) := by
  obtain ⟨owner, hbuild, _, hcheck⟩ := built_owner_correct blst pairs valid room
  rw [hbuild]
  exact hcheck

end

end LeanBlsSimd.PairingProduct
