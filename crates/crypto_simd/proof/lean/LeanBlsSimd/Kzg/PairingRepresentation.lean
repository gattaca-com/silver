import LeanBlsSimd.Kzg.G1Msm
import LeanBlsSimd.Kzg.SetupValidity

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
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


end LeanBlsSimd.Kzg
