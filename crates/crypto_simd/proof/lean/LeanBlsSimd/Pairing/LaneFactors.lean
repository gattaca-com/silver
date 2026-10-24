import LeanBlsSimd.Pairing.LaneLines
import LeanBlsSimd.Proofs.Mmask8

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.Pairing.LaneLines

open LaneTower

set_option maxRecDepth 4000

def PointsRep (raw : g1x8.G1x8) (points : Fin 8 → Bls.G1) : Prop :=
  ∀ l, (ofFp8 raw.x).Holds l (points l).x ∧
    (ofFp8 raw.y).Holds l (points l).y ∧ (ofFp8 raw.z).Holds l (points l).z

def firstPoints (points : Fin 8 → Bls.G1) : Fin 2 → Bls.G1 :=
  fun l => points ⟨l.val, by omega⟩

def factorIndices : Array I64 8#usize := Array.make 8#usize
  [0#i64, 0#i64, 8#i64, 8#i64, 1#i64, 1#i64, 9#i64, 9#i64] (by rfl)

theorem factor_shuffle (points : Fin 8 → Bls.G1) :
    shuffle factorIndices (fun l => (fun (a b : F) => a * b) (points l).x (points l).z) (fun l => (points l).y) =
      packedFactors (g1Factors (firstPoints points)) := by
  funext l
  fin_cases l <;> rfl

theorem factors_refines (raw : g1x8.G1x8) (points : Fin 8 → Bls.G1) (hp : PointsRep raw points) :
    ∃ factors z, (do
      let xz ← fp8.Fp8.mul raw.x raw.z
      let factors ← fp8.Fp8.permute2 xz raw.y factorIndices
      let zz ← fp8.Fp8.square raw.z
      let z ← fp8.Fp8.mul zz raw.z
      ok (factors, z)) = ok (factors, z) ∧
      FactorsRep factors z (g1Factors (firstPoints points)) := by
  obtain ⟨xz, hxz, rxz⟩ := raw_mul (fun l => (hp l).1.capped)
    (fun l => (hp l).2.2.capped) (by intro l; decide)
  obtain ⟨factors, hfac, rfac⟩ := normal_permute2 factorIndices rxz (fun l => (hp l).2.1.capped)
  have hbound : shuffle factorIndices (fun _ => 2) (fun _ => 2) = fun _ => 2 := by
    funext l; simp [shuffle]
  rw [hbound, factor_shuffle] at rfac
  let zz := toFp8 (ofFp8 raw.z).square
  have hzz : fp8.Fp8.square raw.z = ok zz := Fp8.square_refines raw.z
  have rzz : Normal (fun _ => 2) zz (fun l => (points l).z * (points l).z) := by
    intro l
    simpa only [zz, ofFp8_toFp8, sq] using (hp l).2.2.square.capped
  obtain ⟨z, hz, rz⟩ := raw_mul rzz (fun l => (hp l).2.2.capped) (by intro l; decide)
  refine ⟨factors, z, ?_, rfac, _, rz, rfl, rfl⟩
  simp only [hxz, hfac, hzz, hz, bind_tc_ok]

theorem mask_bit (m : UInt8) (l : Fin 8) :
    (toU8 m &&& toU8 (1 <<< l.val.toUInt8) != 0#u8) = m.toNat.testBit l := by
  rw [Bool.eq_iff_iff]
  simp only [bne_iff_ne, toU8_and]
  change (toU8 (m &&& (1 <<< l.val.toUInt8)) ≠ toU8 0 ↔ _)
  simp only [ne_eq, toU8_inj]
  exact Mmask8.and_one_shiftLeft_ne_zero m l

theorem presence_refines (raw : g1x8.G1x8) (points : Fin 8 → Bls.G1) (hp : PointsRep raw points) :
    maskPresence (~~~ toU8 (ofFp8 raw.z).is_zero_mask) = presence (firstPoints points) := by
  rw [toU8_not]
  have h0 := mask_bit (~~~(ofFp8 raw.z).is_zero_mask) 0
  have h1 := mask_bit (~~~(ofFp8 raw.z).is_zero_mask) 1
  change (toU8 (~~~(ofFp8 raw.z).is_zero_mask) &&& 1#u8 != 0#u8) = _ at h0
  change (toU8 (~~~(ofFp8 raw.z).is_zero_mask) &&& 2#u8 != 0#u8) = _ at h1
  rw [Mmask8.testBit_not, (hp 0).2.2.testBit_is_zero_mask] at h0
  rw [Mmask8.testBit_not, (hp 1).2.2.testBit_is_zero_mask] at h1
  have hzero (a : Fp) : a.isZero = decide ((a : F) = 0) := by
    rw [Bool.eq_iff_iff, decide_eq_true_eq, Fp.isZero_iff]
  simp only [maskPresence, h0, h1, presence, firstPoints, Bls.G1.isInfinity, hzero]
  rfl

end LeanBlsSimd.Pairing.LaneLines
