import LeanBlsSimd.PairingProduct.Infinity
import LeanBlsSimd.PairingProduct.BlstContract

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.PairingProduct

noncomputable section

def emptyOwner : pairing_product.PairingProduct := ⟨alloc.vec.Vec.new _⟩

def finitePair (p : pairing_product.AffinePair) : Bool :=
  !((Kzg.g1ReadAffine p.p).isInfinity || (Kzg.g2ReadAffine p.q).isInfinity)

theorem default_empty :
    pairing_product.PairingProduct.Insts.CoreDefaultDefault.default = ok emptyOwner := rfl

theorem with_capacity_empty (capacity : Usize) :
    pairing_product.PairingProduct.with_capacity capacity = ok emptyOwner := rfl

theorem clear_empty (self : pairing_product.PairingProduct) :
    pairing_product.PairingProduct.clear self = ok emptyOwner := rfl

theorem emptyOwner_pairs : emptyOwner.pairs.val = [] := rfl

theorem affinePair_new (p : g1_point.G1Point) (q : g2_point.G2Point) :
    pairing_product.AffinePair.new p q = ok ⟨p, q⟩ := rfl

theorem push_refines (self : pairing_product.PairingProduct)
    (p : g1_point.G1Point) (q : g2_point.G2Point)
    (hp : Kzg.G1AffineValid p) (hq : Kzg.G2AffineValid q)
    (hroom : (self.pairs.val ++ [⟨p, q⟩].filter finitePair).length ≤ Usize.max) :
    ∃ next, pairing_product.PairingProduct.push self p q = ok next ∧
      next.pairs.val = self.pairs.val ++ [⟨p, q⟩].filter finitePair := by
  rw [pairing_product.PairingProduct.push, affinePair_new]
  simp only [bind_tc_ok]
  rw [affinePair_is_infinite ⟨p, q⟩ hp hq]
  simp only [bind_tc_ok]
  by_cases hi : ((Kzg.g1ReadAffine p).isInfinity || (Kzg.g2ReadAffine q).isInfinity) = true
  · refine ⟨self, ?_, ?_⟩
    · simp only [hi, if_true]
    · simp [finitePair, hi]
  · have hbound : self.pairs.val.length < Usize.max := by
      simpa [finitePair, hi] using hroom
    obtain ⟨ps, hps, hval⟩ := WP.spec_imp_exists (alloc.vec.Vec.push_spec self.pairs ⟨p, q⟩ hbound)
    refine ⟨⟨ps⟩, ?_, ?_⟩
    · simp only [hi, Bool.false_eq_true, if_false, hps, bind_tc_ok]
    · simpa [finitePair, hi] using hval

theorem push_preserves_valid (self : pairing_product.PairingProduct)
    (p : g1_point.G1Point) (q : g2_point.G2Point)
    (valid : ∀ pair ∈ self.pairs.val, Kzg.G1AffineValid pair.p ∧ Kzg.G2AffineValid pair.q)
    (hp : Kzg.G1AffineValid p) (hq : Kzg.G2AffineValid q)
    (hroom : (self.pairs.val ++ [⟨p, q⟩].filter finitePair).length ≤ Usize.max) :
    ∃ next, pairing_product.PairingProduct.push self p q = ok next ∧
      next.pairs.val = self.pairs.val ++ [⟨p, q⟩].filter finitePair ∧
      ∀ pair ∈ next.pairs.val, Kzg.G1AffineValid pair.p ∧ Kzg.G2AffineValid pair.q := by
  obtain ⟨next, hnext, hval⟩ := push_refines self p q hp hq hroom
  refine ⟨next, hnext, hval, ?_⟩
  intro pair hm
  rw [hval] at hm
  rcases List.mem_append.mp hm with hm | hm
  · exact valid pair hm
  · have he : pair = ⟨p, q⟩ := by simpa using (List.mem_filter.mp hm).1
    subst pair
    exact ⟨hp, hq⟩

theorem is_one_empty [RuntimeFeatures] [PairingExternals]
    (self : pairing_product.PairingProduct) (h : self.pairs.val = []) :
    pairing_product.PairingProduct.is_one self = ok true := by
  simp [pairing_product.PairingProduct.is_one, pairing_product.PairingInputs.check,
    core.slice.Slice.is_empty, Slice.length, alloc.vec.Vec.deref, h]

private theorem next_zero_two :
    core.iter.range.IteratorRange.next core.iter.range.StepUsize
      { start := 0#usize, «end» := 2#usize } =
        ok (some 0#usize, { start := 1#usize, «end» := 2#usize }) := by
  obtain ⟨⟨s, e⟩, hs, he, hn⟩ := next_lt
    { start := 0#usize, «end» := 2#usize } (by decide)
  have hs' : s = 1#usize := UScalar.eq_of_val_eq (by simpa using hs)
  simpa only [hs', show e = 2#usize from he] using hn

private theorem next_one_two :
    core.iter.range.IteratorRange.next core.iter.range.StepUsize
      { start := 1#usize, «end» := 2#usize } =
        ok (some 1#usize, { start := 2#usize, «end» := 2#usize }) := by
  obtain ⟨⟨s, e⟩, hs, he, hn⟩ := next_lt
    { start := 1#usize, «end» := 2#usize } (by decide)
  have hs' : s = 2#usize := UScalar.eq_of_val_eq (by simpa using hs)
  simpa only [hs', show e = 2#usize from he] using hn

private theorem next_two_two :
    core.iter.range.IteratorRange.next core.iter.range.StepUsize
      { start := 2#usize, «end» := 2#usize } =
        ok (none, { start := 2#usize, «end» := 2#usize }) :=
  next_ge _ (by decide)

private def twoArray (a b : pairing_product.AffinePair) : Array pairing_product.AffinePair 2#usize :=
  ⟨[a, b], rfl⟩

private theorem two_loop_refines (a b : pairing_product.AffinePair)
    (ha : Kzg.G1AffineValid a.p) (ha' : Kzg.G2AffineValid a.q)
    (hb : Kzg.G1AffineValid b.p) (hb' : Kzg.G2AffineValid b.q) :
    pairing_product.PairingProduct.two_pairs_are_one_loop
      { start := 0#usize, «end» := 2#usize } (twoArray a b) 0#usize =
      ok (if finitePair a then
        (twoArray a b, if finitePair b then 2#usize else 1#usize)
      else if finitePair b then (twoArray b b, 1#usize) else (twoArray a b, 0#usize)) := by
  have hia := affinePair_is_infinite a ha ha'
  have hib := affinePair_is_infinite b hb hb'
  by_cases hfa : ((Kzg.g1ReadAffine a.p).isInfinity || (Kzg.g2ReadAffine a.q).isInfinity) = true <;>
    by_cases hfb : ((Kzg.g1ReadAffine b.p).isInfinity || (Kzg.g2ReadAffine b.q).isInfinity) = true <;>
    simp only [finitePair, hfa, hfb, Bool.not_true, Bool.not_false, Bool.false_eq_true,
      if_false, if_true] <;>
    unfold pairing_product.PairingProduct.two_pairs_are_one_loop <;>
    iterate 3
      rw [loop.eq_1]
      simp (disch := decide) only [
      pairing_product.PairingProduct.two_pairs_are_one_loop.body,
      next_zero_two, next_one_two, next_two_two, bind_tc_ok, Function.uncurry_apply_pair,
      index_usize_eq, update_eq, twoArray, List.getElem_cons_zero, List.getElem_cons_succ,
      UScalar.ofNatCore_val_eq, hia, hib, hfa, hfb, Bool.false_eq_true, if_true, if_false, Aeneas.Std.Array.set,
      List.set_cons_zero, List.set_cons_succ, usize_add_ok]

def filteredTwo (a b : pairing_product.AffinePair) : Slice pairing_product.AffinePair :=
  ⟨[a, b].filter finitePair, by
    have h := List.length_filter_le finitePair [a, b]
    have := two_pow_32_le_usize
    simp only [List.length_cons, List.length_nil] at h
    simp only [Usize.max_def, Usize.numBits_def]
    omega⟩

theorem two_pairs_filter [RuntimeFeatures] [PairingExternals]
    (first second : g1_point.G1Point × g2_point.G2Point)
    (hp : Kzg.G1AffineValid first.1) (hq : Kzg.G2AffineValid first.2)
    (hp' : Kzg.G1AffineValid second.1) (hq' : Kzg.G2AffineValid second.2) :
    pairing_product.PairingProduct.two_pairs_are_one first second =
      pairing_product.PairingInputs.check
        ⟨filteredTwo ⟨first.1, first.2⟩ ⟨second.1, second.2⟩⟩ := by
  rcases first with ⟨p, q⟩
  rcases second with ⟨p', q'⟩
  simp only [pairing_product.PairingProduct.two_pairs_are_one, affinePair_new,
    bind_tc_ok, Function.uncurry_apply_pair]
  rw [show Array.make 2#usize [⟨p, q⟩, ⟨p', q'⟩] (by rfl) =
    twoArray ⟨p, q⟩ ⟨p', q'⟩ from rfl]
  rw [two_loop_refines _ _ hp hq hp' hq']
  cases hfa : finitePair ⟨p, q⟩ <;>
    cases hfb : finitePair ⟨p', q'⟩ <;>
    simp [hfa, hfb, core.array.Array.index, core.ops.index.IndexSlice,
      core.slice.index.Slice.index, core.slice.index.SliceIndexRangeToUsizeSlice.index,
      twoArray, filteredTwo, Array.to_slice, Slice.length, List.slice]

end

end LeanBlsSimd.PairingProduct
