import LeanBlsSimd.PairingProduct.Inputs
import LeanBlsSimd.PairingProduct.Combined
import LeanBlsSimd.PairingProduct.Owner
import LeanBlsSimd.PairingProduct.LaneMiller
import LeanBlsSimd.PairingProduct.ProductLoop
import LeanBlsSimd.Pairing.SetupEmbedding

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.PairingProduct

noncomputable section

private theorem g1_affine_coordinates (p : blst.blst_p1_affine)
    (hp : (Kzg.g1ReadAffine p).isInfinity = false) :
    (Kzg.g1ReadAffine p).toAffine = (Kzg.fpRead p.x, Kzg.fpRead p.y) := by
  by_cases hz : ((Kzg.fpRead p.x).isZero && (Kzg.fpRead p.y).isZero) = true
  · simp [Kzg.g1ReadAffine, hz, G1.zero, G1.isInfinity] at hp
    cases hp
  · simpa only [Kzg.g1ReadAffine, hz, if_false] using
      Kzg.g1_toAffine_of_one (Kzg.fpRead p.x) (Kzg.fpRead p.y)

private theorem g2_affine_coordinates (q : blst.blst_p2_affine)
    (hq : (Kzg.g2ReadAffine q).isInfinity = false) :
    (Kzg.g2ReadAffine q).toAffine = (Kzg.fp2Read q.x, Kzg.fp2Read q.y) := by
  by_cases hz : ((Kzg.fp2Read q.x).isZero && (Kzg.fp2Read q.y).isZero) = true
  · simp [Kzg.g2ReadAffine, hz, G2.zero, G2.isInfinity] at hq
    cases hq
  · simpa only [Kzg.g2ReadAffine, hz, if_false] using
      Pairing.g2_affine_of_z_one ⟨Kzg.fp2Read q.x, Kzg.fp2Read q.y, Fp2.one⟩ rfl

private def input (p : pairing_product.AffinePair) : Miller.Input :=
  Miller.Input.ofPoints (Kzg.g1ReadAffine p.p) (Kzg.g2ReadAffine p.q)

private theorem input_coordinates (p : pairing_product.AffinePair)
    (hp : finitePair p = true) :
    input p = ⟨Lanes.scalar (Kzg.fpRead p.p.x), Lanes.scalar (Kzg.fpRead p.p.y),
      Fp2.toField (Kzg.fp2Read p.q.x), Fp2.toField (Kzg.fp2Read p.q.y)⟩ := by
  have hf : (Kzg.g1ReadAffine p.p).isInfinity = false ∧
      (Kzg.g2ReadAffine p.q).isInfinity = false := by
    simpa [finitePair] using hp
  simp only [input, Miller.Input.ofPoints, g1_affine_coordinates _ hf.1,
    g2_affine_coordinates _ hf.2, Fp2.toField_ofFp]
  rfl

private theorem initial_holds (pairs : Slice pairing_product.AffinePair)
    (hlo : 1 ≤ pairs.val.length) (hhi : pairs.val.length ≤ 8)
    (valid : ∀ p ∈ pairs.val, Kzg.G1AffineValid p.p ∧ Kzg.G2AffineValid p.q)
    (finite : ∀ p ∈ pairs.val, finitePair p = true) :
    ∃ raw, lane_pairs.LanePairs.new pairs = ok raw ∧
      LaneMiller.Holds (Lanes.ofState raw) (Miller.initialEntries (pairs.val.map input)) := by
  obtain ⟨raw, hr, hcount, hflag, hlane⟩ := Lanes.new_holds pairs hlo hhi valid
  refine ⟨raw, hr, ?_, ?_, ?_, ?_⟩
  · simpa only [Lanes.ofState, hcount] using hlo
  · simpa only [Lanes.ofState, hcount] using hhi
  · simp only [Miller.initialEntries, List.length_map, Lanes.ofState, hcount]
  · intro l hl
    have hl' : l.val < pairs.val.length := by
      simpa only [Miller.initialEntries, List.length_map] using hl
    have hc := input_coordinates pairs.val[l.val] (finite _ (List.getElem_mem hl'))
    simp only [Miller.initialEntries, List.getElem_map]
    change LaneMiller.EntryHolds (Lanes.ofState raw) l
      (input pairs.val[l.val], (input pairs.val[l.val]).initial)
    rw [hc]
    refine ⟨Kzg.fpRead pairs.val[l.val].p.x, Kzg.fpRead pairs.val[l.val].p.y,
      rfl, rfl, hlane l hl', ?_⟩
    simp [Lanes.ofState, hflag, Miller.Input.initial, ofU8]

private theorem factor_spec (pairs : List pairing_product.AffinePair)
    (finite : ∀ p ∈ pairs, finitePair p = true)
    (clear : Miller.flags (Miller.sharedMiller (pairs.map input)).1 = false) :
    Miller.sharedFactor (pairs.map input) ^ finalExpExponent =
      ProductLoop.factorProduct pairs ^ finalExpExponent := by
  let points := pairs.map fun p => (Kzg.g1ReadAffine p.p, Kzg.g2ReadAffine p.q)
  have hf : ∀ pair ∈ points, pair.1.isInfinity = false ∧ pair.2.isInfinity = false := by
    intro pair hm
    obtain ⟨p, hp, rfl⟩ := List.mem_map.mp hm
    simpa [finitePair] using finite p hp
  have hc : Miller.flags (Miller.sharedMiller
      (points.map fun pair => Miller.Input.ofPoints pair.1 pair.2)).1 = false := by
    simpa only [points, List.map_map, Function.comp_def, input] using clear
  simpa only [points, List.map_map, Function.comp_def, input, ProductLoop.factorProduct]
    using Miller.finite_sharedFactor_spec points
      (fun p hp => (hf p hp).1) (fun p hp => (hf p hp).2) hc

theorem single_set_correct : ProductLoop.SingleSetCorrect := by
  intro pairs hlo hhi valid finite
  obtain ⟨raw, hnew, hraw⟩ := initial_holds pairs hlo hhi valid finite
  obtain ⟨result, hloop, hrep, hclear⟩ :=
    LaneMiller.miller_refines raw (pairs.val.map input) hraw
  refine ⟨result, ?_, Miller.sharedFactor (pairs.val.map input), hrep, ?_⟩
  · simp only [hnew, bind_tc_ok, hloop]
  · intro hc
    exact factor_spec pairs.val finite (hclear hc)

end

end LeanBlsSimd.PairingProduct
