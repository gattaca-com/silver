import LeanBlsSimd.Kzg.PairingTable
import LeanBlsSimd.Extracted.Funs
import LeanBlsSimd.Kzg.SetupPoints
import LeanBlsSimd.Kzg.Model
import LeanBlsSimd.Kzg.CosetsRep
import LeanBlsSimd.Kzg.InterpolationKernel.Basic

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls
open private buildEmbedded from EthLib.Cryptography.Kzg.TrustedSetup

namespace LeanBlsSimd.Kzg

set_option maxRecDepth 16000
set_option maxHeartbeats 8000000

def embeddedSetup : TrustedSetup := buildEmbedded

def rustG1Bytes : _root_.Array ByteArray :=
  (trusted_setup.G1_MONOMIAL.val.map arrayBytes).toArray

def rustG2ZeroBytes : ByteArray := arrayBytes SetupPoints.g2Bytes0
def rustG2CellBytes : ByteArray := arrayBytes SetupPoints.g2Bytes64

theorem specPoint_of_decoded (b : ByteArray) (p : G1)
    (hd : G1.uncompress b = .ok p) (hi : p.isInfinity = false)
    (hs : p.inSubgroup = true) : specPoint b = some p := by
  simp [specPoint, bytesToKzgProof, validateKzgG1, G1.keyValidate, hd, hi, hs,
    Bind.bind, Except.bind, Pure.pure, Except.pure, Except.isOk, Except.toBool, Except.toOption]

theorem g1_setup_specPoint (i : Fin 64) :
    specPoint (arrayBytes trusted_setup.G1_MONOMIAL.val[i.val]!) =
      some SetupPoints.g1Points[i.val]! :=
  specPoint_of_decoded _ _ (SetupPoints.g1_decoded i)
    (SetupPoints.g1_finite i) (SetupPoints.g1_subgroup i)

def SetupMatches (s : TrustedSetup) : Prop :=
  s.g1MonomialBytes.extract 0 64 = rustG1Bytes ∧
  s.g2Monomial.size > 64 ∧
  G2.uncompress rustG2ZeroBytes = .ok s.g2Monomial[0]! ∧
  G2.uncompress rustG2CellBytes = .ok s.g2Monomial[64]! ∧
  s.g2Monomial[0]!.inSubgroup = true ∧ s.g2Monomial[64]!.inSubgroup = true ∧
  ∀ b ∈ rustG1Bytes, ∃ p, specPoint b = some p

theorem embedded_g1_bytes : embeddedSetup.g1MonomialBytes.extract 0 64 = rustG1Bytes := by
  apply _root_.Array.toList_inj.mp
  rw [_root_.Array.toList_extract, List.extract_eq_take_drop]
  simp only [embeddedSetup, buildEmbedded, _root_.Array.toList_map]
  decide +kernel

theorem embedded_g2_size : embeddedSetup.g2Monomial.size = 65 := by
  simp only [embeddedSetup, buildEmbedded, Array.size_map]
  decide +kernel

theorem embedded_g2_bytes_zero : embeddedSetup.g2MonomialBytes[0]! = rustG2ZeroBytes := by
  decide +kernel

theorem embedded_g2_bytes_cell : embeddedSetup.g2MonomialBytes[64]! = rustG2CellBytes := by
  decide +kernel

theorem embedded_g2_get (i : Nat) (hi : i < 65) (p : G2)
    (hd : G2.uncompress embeddedSetup.g2MonomialBytes[i]! = .ok p) :
    embeddedSetup.g2Monomial[i]! = p := by
  have hb : i < embeddedSetup.g2MonomialBytes.size := by
    have hs : embeddedSetup.g2MonomialBytes.size = 65 := by decide +kernel
    omega
  rw [getElem!_pos embeddedSetup.g2Monomial i (by rw [embedded_g2_size]; exact hi)]
  rw [getElem!_pos embeddedSetup.g2MonomialBytes i hb] at hd
  simp only [embeddedSetup, buildEmbedded, _root_.Array.getElem_map] at hd ⊢
  rw [hd]

theorem embedded_g2_zero : embeddedSetup.g2Monomial[0]! = SetupPoints.g2Point0 := by
  apply embedded_g2_get 0 (by decide)
  rw [embedded_g2_bytes_zero, rustG2ZeroBytes, SetupPoints.g2_0_decoded]

theorem embedded_g2_cell : embeddedSetup.g2Monomial[64]! = SetupPoints.g2Point64 := by
  apply embedded_g2_get 64 (by decide)
  rw [embedded_g2_bytes_cell, rustG2CellBytes, SetupPoints.g2_64_decoded]

theorem embedded_setup_matches : SetupMatches embeddedSetup := by
  refine ⟨embedded_g1_bytes, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · rw [embedded_g2_size]; decide
  · rw [embedded_g2_zero]; exact SetupPoints.g2_0_decoded
  · rw [embedded_g2_cell]; exact SetupPoints.g2_64_decoded
  · rw [embedded_g2_zero]; exact SetupPoints.g2_0_subgroup
  · rw [embedded_g2_cell]; exact SetupPoints.g2_64_subgroup
  · intro b hb
    obtain ⟨j, hj, rfl⟩ := _root_.Array.mem_iff_getElem.mp hb
    have hlen : rustG1Bytes.size = 64 := by simp [rustG1Bytes]
    have hj64 : j < 64 := by omega
    refine ⟨SetupPoints.g1Points[j]!, ?_⟩
    have h := g1_setup_specPoint ⟨j, hj64⟩
    have hlength : j < trusted_setup.G1_MONOMIAL.val.length := by simpa using hj64
    simpa only [rustG1Bytes, List.getElem_toArray, List.getElem_map,
      getElem!_pos trusted_setup.G1_MONOMIAL.val j hlength] using h

def SetupRep (s : setup.Setup) : Prop :=
  s.g1_monomial.val =
    rustG1Bytes.toList.map (fun b => g1Affine ((specPoint b).getD G1.zero))


def StateInvariant (v : verify.CellBatchVerifier) : Prop :=
  SetupRep v.setup ∧ CosetsRep v.cosets ∧
  (match v.kernel with
  | none => True
  | some kernel => InterpolationKernel.StateInvariant kernel) ∧
  CurveWorkInvariant v.curve_work

end LeanBlsSimd.Kzg
