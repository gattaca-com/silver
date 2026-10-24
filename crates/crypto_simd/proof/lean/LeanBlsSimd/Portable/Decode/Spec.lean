import LeanBlsSimd.Portable.Decode.Ordinary
import LeanBlsSimd.Portable.Decode.Infinity
import LeanBlsSimd.Portable.G1.Exclusions

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Decode
open DecompressG1
set_option maxRecDepth 4096

abbrev Ordinary (b : Encoding) : Prop :=
  (decodeLane b).undecided = false ∧ (decodeLane b).invalid = false ∧ (decodeLane b).x ≠ 0

theorem ordinary_eq (b : Encoding) : ordinary b =
    if Ordinary b then some (words b,(decodeLane b).largerRoot) else none := by
  unfold ordinary Ordinary decodeLane
  dsimp only
  split_ifs <;> simp_all

theorem ordinary_some {b : Encoding} (ho : Ordinary b) :
    ordinary b = some (words b,(decodeLane b).largerRoot) := by
  rw [ordinary_eq,if_pos ho]

private theorem undecided_zero {b : Encoding} {P : Bls.G1}
    (hu : (decodeLane b).undecided = true) (hd : Bls.G1.uncompress (G1Spec.toBytes b) = .ok P) :
    P = Bls.G1.zero := by
  have hi : b[0] &&& 0x40 ≠ 0 := by
    unfold decodeLane at hu
    dsimp only at hu
    split_ifs at hu <;> simp_all
  unfold Bls.G1.uncompress at hd
  generalize Bls.Fp.sqrt = sq at hd
  rw [if_neg (by rw [size_toBytes]; decide)] at hd
  dsimp only at hd
  rw [get!_toBytes_zero] at hd
  split at hd
  · contradiction
  split at hd
  · contradiction
  exact (Except.ok.inj hd).symm

private theorem invalid_verdict {b : Encoding} (hv : (decodeLane b).invalid = true) :
    G1Spec.verdict b = none := by
  rw [G1Spec.verdict_eq_decode]
  cases hd : Bls.G1.uncompress (G1Spec.toBytes b) with
  | error => rfl
  | ok P => exact False.elim (uncompress_of_invalid (invalid_undecided hv) hv P hd)

private theorem zero_x_verdict {b : Encoding} (hu : (decodeLane b).undecided = false)
    (hv : (decodeLane b).invalid = false) (hx : (decodeLane b).x = 0) :
    G1Spec.verdict b = none := by
  rw [G1Spec.verdict_eq_decode,uncompress_decoded hu hv]
  split_ifs with hr
  · have hp := lanePoint_valid hr
    have he : laneX b = 0 := by simp only [laneX,hx,Nat.cast_zero]
    have hs : Bls.G1.inSubgroup (lanePoint b) = false := by
      simpa only [lanePoint,he] using G1.x_zero_not_in_subgroup (laneY b)
        (by simpa only [lanePoint,he] using hp)
    simp only [hs,Bool.false_eq_true,if_false]
  · rfl

theorem nonordinary_verdict {b : Encoding} (ho : ¬Ordinary b) :
    G1Spec.verdict b = if b = G1Spec.infinity then
      some (point (.replicate 6 0) (.replicate 6 0)) else none := by
  by_cases hb : b = G1Spec.infinity
  · subst b
    rw [if_pos rfl,G1Spec.infinity_verdict]
  rw [if_neg hb]
  by_cases hv : (decodeLane b).invalid = true
  · exact invalid_verdict hv
  have hvf : (decodeLane b).invalid = false := Bool.eq_false_iff.mpr hv
  by_cases hu : (decodeLane b).undecided = true
  · rw [G1Spec.verdict_eq_decode]
    cases hd : Bls.G1.uncompress (G1Spec.toBytes b) with
    | error => rfl
    | ok P =>
      have hz := undecided_zero hu hd
      subst P
      exact False.elim (hb ((G1Spec.infinity_decoding_iff b).mp hd))
  · have huf : (decodeLane b).undecided = false := Bool.eq_false_iff.mpr hu
    have hx : (decodeLane b).x = 0 := by
      by_contra hn
      exact ho ⟨huf,hvf,hn⟩
    exact zero_x_verdict huf hvf hx

end LeanBlsSimd.Portable.Decode
