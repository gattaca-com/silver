import LeanBlsSimd.Kzg.G1Msm
import LeanBlsSimd.Kzg.SetupValidity

open Aeneas Aeneas.Std Result
open EthCryptographySpecs Bls
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

theorem embedded_ofG1_eq {p q : G1} (hinf : p.isInfinity = q.isInfinity)
    (haff : p.toAffine = q.toAffine) : Embedded.ofG1 p = Embedded.ofG1 q := by
  simp only [Embedded.ofG1, hinf, haff]

theorem pairingCheck_two_congr {p₀ p₁ q₀ q₁ : G1} (s₀ s₁ : G2)
    (h₀i : p₀.isInfinity = q₀.isInfinity) (h₀a : p₀.toAffine = q₀.toAffine)
    (h₁i : p₁.isInfinity = q₁.isInfinity) (h₁a : p₁.toAffine = q₁.toAffine) :
    Bls.pairingCheck #[(p₀, s₀), (p₁, s₁)] =
      Bls.pairingCheck #[(q₀, s₀), (q₁, s₁)] := by
  unfold Bls.pairingCheck
  simp only [← _root_.Array.forIn_toList]
  simp only [List.forIn_cons, List.forIn_nil, h₀i, h₁i,
    embedded_ofG1_eq h₀i h₀a, embedded_ofG1_eq h₁i h₁a]

theorem g1Rep_trans {raw : blst.blst_p1} {p q : G1} (hr : G1Rep raw p)
    (hinf : p.isInfinity = q.isInfinity) (haff : p.toAffine = q.toAffine) :
    G1Rep raw q := ⟨hr.1, hr.2.1.trans hinf, hr.2.2.trans haff⟩

theorem g1_msm_valid_of_mem (points : _root_.Array G1) (scalars : _root_.Array Fr)
    (hvalid : ∀ p ∈ points, G1Valid p) : G1Valid (G1.msm points scalars) := by
  apply g1Valid_msm
  intro j hj
  have hn : (if points.size ≤ scalars.size then points.size else scalars.size) ≤
      points.size := by split <;> omega
  have hjp := Nat.lt_of_lt_of_le hj hn
  rw [getElem!_pos points j hjp]
  exact hvalid _ (_root_.Array.getElem_mem hjp)

theorem g1_lincomb_refinement [e : KzgExternals] (h : ExternalsCorrect e)
    (ps : alloc.vec.Vec blst.blst_p1_affine) (fs : alloc.vec.Vec blst.blst_fr)
    (points : _root_.Array G1) (scalars : _root_.Array Fr)
    (hps : ps.val = points.toList.map g1Affine) (hfs : fs.val = scalars.toList.map frEncode)
    (hsize : points.size = scalars.size) (hvalid : ∀ p ∈ points, G1Valid p)
    (scratch : blst_ops.LincombScratch) :
    ∃ point scratch', blst_ops.g1_lincomb (alloc.vec.Vec.deref ps)
      (alloc.vec.Vec.deref fs) scratch = ok (point, scratch') ∧
      G1Rep point (G1.msm points scalars) := by
  have hlen : (alloc.vec.Vec.deref ps).val.length = (alloc.vec.Vec.deref fs).val.length := by
    simp only [alloc.vec.Vec.deref, hps, hfs, List.length_map, _root_.Array.length_toList, hsize]
  have hpv : ∀ p ∈ (alloc.vec.Vec.deref ps).val, G1AffineValid p := by
    intro p hp
    simp only [alloc.vec.Vec.deref, hps] at hp
    obtain ⟨q, hq, rfl⟩ := List.mem_map.mp hp
    exact g1Affine_valid (hvalid q (_root_.Array.mem_toList_iff.mp hq))
  have hfv : ∀ f ∈ (alloc.vec.Vec.deref fs).val, FrReduced f := by
    intro f hf
    simp only [alloc.vec.Vec.deref, hfs] at hf
    obtain ⟨q, _, rfl⟩ := List.mem_map.mp hf
    exact frEncode_reduced q
  obtain ⟨point, scratch', hcall, hrep⟩ := h.blst.lincomb
    (alloc.vec.Vec.deref ps) (alloc.vec.Vec.deref fs) scratch hlen hpv hfv
  have hreadp : ((alloc.vec.Vec.deref ps).val.map g1ReadAffine).toArray =
      points.map (fun p => g1ReadAffine (g1Affine p)) := by
    simp only [alloc.vec.Vec.deref, hps, List.map_map, ← List.map_toArray,
      _root_.Array.toArray_toList, Function.comp_def]
  have hreadf : ((alloc.vec.Vec.deref fs).val.map frRead).toArray = scalars := by
    simp only [alloc.vec.Vec.deref, hfs, List.map_map, Function.comp_def, frRead_frEncode,
      List.map_id', _root_.Array.toArray_toList]
  rw [hreadp, hreadf] at hrep
  have hvj : ∀ j, j < points.size → G1Valid points[j]! := by
    intro j hj
    rw [getElem!_pos points j hj]
    exact hvalid _ (_root_.Array.getElem_mem hj)
  have hget : ∀ j (hj : j < points.size),
      (points.map (fun p => g1ReadAffine (g1Affine p)))[j]! =
        g1ReadAffine (g1Affine points[j]!) := by
    intro j hj
    rw [getElem!_pos _ j (by simpa using hj), _root_.Array.getElem_map,
      getElem!_pos points j hj]
  have hn : (if points.size ≤ scalars.size then points.size else scalars.size) ≤
      points.size := by split <;> omega
  obtain ⟨_, _, hinf, haff⟩ := g1_msm_congr points
    (points.map (fun p => g1ReadAffine (g1Affine p))) scalars (by simp)
    (fun j hj => hvj j (Nat.lt_of_lt_of_le hj hn))
    (fun j hj => by
      have hjp := Nat.lt_of_lt_of_le hj hn
      rw [hget j hjp]
      exact (g1ReadAffine_g1Affine_matches (hvj j hjp)).1.symm)
    (fun j hj => by
      have hjp := Nat.lt_of_lt_of_le hj hn
      rw [hget j hjp]
      exact (g1ReadAffine_g1Affine_matches (hvj j hjp)).2.symm)
  exact ⟨point, scratch', hcall, g1Rep_trans hrep hinf.symm haff.symm⟩

theorem g1_neg_refinement [e : KzgExternals] (h : ExternalsCorrect e)
    (raw : blst.blst_p1) (p : G1) (hr : G1Rep raw p) (hp : G1Valid p) :
    ∃ result, blst_ops.g1_neg raw = ok result ∧ G1Rep result (G1.neg p) := by
  have hv := g1Valid_of_rep hr hp
  obtain ⟨result, hcall, hrep⟩ := h.blst.g1_neg raw hr.1 hv
  have hm := g1_neg_matches hv hp hr.2.1 hr.2.2
  exact ⟨result, hcall, g1Rep_trans hrep hm.1 hm.2⟩

theorem g1_add_refinement [e : KzgExternals] (h : ExternalsCorrect e)
    (left right : blst.blst_p1) (p q : G1) (hl : G1Rep left p) (hr : G1Rep right q)
    (hp : G1Valid p) (hq : G1Valid q) :
    ∃ result, blst_ops.g1_add left right = ok result ∧ G1Rep result (G1.add p q) := by
  have hvl := g1Valid_of_rep hl hp
  have hvr := g1Valid_of_rep hr hq
  obtain ⟨result, hcall, hrep⟩ := h.blst.g1_add left right hl.1 hr.1 hvl hvr
  have hm := g1_add_matches hvl hvr hp hq hl.2.1 hl.2.2 hr.2.1 hr.2.2
  exact ⟨result, hcall, g1Rep_trans hrep hm.1 hm.2⟩

private theorem setup_byte_model (b : ByteArray) (hb : b ∈ rustG1Bytes) :
    (specPoint b).getD G1.zero = (G1.uncompress b).toOption.getD G1.zero ∧
      G1Valid ((specPoint b).getD G1.zero) := by
  have hbl : b ∈ rustG1Bytes.toList := _root_.Array.mem_toList_iff.mpr hb
  simp only [rustG1Bytes, List.toList_toArray] at hbl
  obtain ⟨raw, hraw, rfl⟩ := List.mem_map.mp hbl
  obtain ⟨j, hj, rfl⟩ := List.mem_iff_getElem.mp hraw
  have hj64 : j < 64 := by simpa using hj
  have hp := g1_setup_specPoint ⟨j, hj64⟩
  have hd := SetupPoints.g1_decoded ⟨j, hj64⟩
  rw [getElem!_pos trusted_setup.G1_MONOMIAL.val j hj] at hp hd
  simp only [hp, hd, Except.toOption, Option.getD_some]
  exact ⟨trivial, setup_g1_valid ⟨j, hj64⟩⟩

theorem setup_model_points_eq :
    rustG1Bytes.map (fun b => (specPoint b).getD G1.zero) =
      (embeddedSetup.g1MonomialBytes.extract 0 64).map
        (fun b => (G1.uncompress b).toOption.getD G1.zero) := by
  rw [embedded_g1_bytes]
  exact _root_.Array.map_congr_left (fun b hb => (setup_byte_model b hb).1)

theorem setup_model_points_valid :
    ∀ p ∈ rustG1Bytes.map (fun b => (specPoint b).getD G1.zero), G1Valid p := by
  intro p hp
  obtain ⟨b, hb, rfl⟩ := _root_.Array.mem_map.mp hp
  exact (setup_byte_model b hb).2

theorem pairing_call_refinement [e : KzgExternals] (h : ExternalsCorrect e)
    (s : setup.Setup) (hs : SetupRep s) (left right : blst.blst_p1) (p q : G1)
    (hl : G1Rep left p) (hr : G1Rep right q) (hp : G1Valid p) (hq : G1Valid q) :
    (do
      let l ← blst_ops.g1_to_affine left
      let r ← blst_ops.g1_to_affine right
      blst_ops.pairing_check l s.g2_s_pow_cell r s.g2_neg_generator) =
      ok (Bls.pairingCheck #[(p, embeddedSetup.g2Monomial[64]!),
        (q, G2.neg embeddedSetup.g2Monomial[0]!)]) := by
  have hvl := g1Valid_of_rep hl hp
  have hvr := g1Valid_of_rep hr hq
  have hcl : blst_ops.g1_to_affine left = ok (g1Affine (g1ReadJacobian left)) :=
    h.blst.g1_affine left hl.1 hvl
  have hcr : blst_ops.g1_to_affine right = ok (g1Affine (g1ReadJacobian right)) :=
    h.blst.g1_affine right hr.1 hvr
  have hsc : G2AffineValid (g2Affine embeddedSetup.g2Monomial[64]!) := by
    rw [embedded_g2_cell]
    exact setup_g2_cell_valid
  have hsn : G2AffineValid (g2Affine (G2.neg embeddedSetup.g2Monomial[0]!)) := by
    rw [embedded_g2_zero]
    exact setup_g2_neg_zero_valid
  have hrc : g2ReadAffine (g2Affine embeddedSetup.g2Monomial[64]!) =
      embeddedSetup.g2Monomial[64]! := by
    rw [embedded_g2_cell]
    exact setup_g2_cell_roundtrip
  have hrn : g2ReadAffine (g2Affine (G2.neg embeddedSetup.g2Monomial[0]!)) =
      G2.neg embeddedSetup.g2Monomial[0]! := by
    rw [embedded_g2_zero]
    exact setup_g2_neg_zero_roundtrip
  simp only [hcl, hcr, bind_tc_ok, hs.2.1, hs.2.2]
  change e.pairingCheck _ _ _ _ = _
  rw [h.blst.pairing _ _ _ _ (g1Affine_valid hvl) hsc (g1Affine_valid hvr) hsn,
    hrc, hrn]
  apply congrArg ok
  have hml := g1ReadAffine_g1Affine_matches hvl
  have hmr := g1ReadAffine_g1Affine_matches hvr
  exact pairingCheck_two_congr _ _ (hml.1.trans hl.2.1) (hml.2.trans hl.2.2)
    (hmr.1.trans hr.2.1) (hmr.2.trans hr.2.2)

end LeanBlsSimd.Kzg
