import LeanBlsSimd.Proofs.G1x8
import LeanBlsSimd.Proofs.G1KernelFacts

namespace LeanBlsSimd

open EthLib.Cryptography.Bls

namespace DecompressG1

theorem valid_sound (inputs : Vector Encoding 8) (l : Fin 8)
    (hv : (decompress inputs).valid.toNat.testBit l = true) :
    ∃ P, G1.uncompress (G1Spec.toBytes inputs[l]) = .ok P ∧ G1.inSubgroup P = true ∧
      (decompress inputs).points[l] = G1Spec.blstLimbs P ∧
      (decompress inputs).undecided.toNat.testBit l = false := by
  have hf := decompress_lane inputs l
  have hv' := hv
  rw [hf.valid, Bool.and_eq_true, Bool.and_eq_true, Bool.and_eq_true,
    Bool.not_eq_true', Bool.not_eq_true'] at hv'
  obtain ⟨⟨⟨hsq, hm⟩, hu⟩, hi⟩ := hv'
  have hroot := of_decide_eq_true hsq
  have hu' := hu
  rw [hf.undecided, hi, Bool.not_false, Bool.and_true,
    Bool.or_eq_false_iff, Bool.or_eq_false_iff] at hu'
  obtain ⟨⟨hdu, _⟩, hmu⟩ := hu'
  have hp := lanePoint_valid hroot
  have hmem := (G1x8.scott_membership_iff (xOf inputs) (yOf inputs) l
    (laneX inputs[l]) (laneY inputs[l]) (lane_x inputs l) (lane_y inputs l) hp hmu).mp hm
  refine ⟨lanePoint inputs[l], ?_, hmem, hf.points, hu⟩
  rw [uncompress_decoded hdu hi, if_pos hroot]

theorem valid_complete (inputs : Vector Encoding 8) (l : Fin 8)
    (hu : (decompress inputs).undecided.toNat.testBit l = false)
    (h : (G1Spec.verdict inputs[l]).isSome = true) :
    (decompress inputs).valid.toNat.testBit l = true := by
  have hf := decompress_lane inputs l
  rw [G1Spec.verdict_eq_decode] at h
  cases he : G1.uncompress (G1Spec.toBytes inputs[l]) with
  | error e => rw [he] at h; cases h
  | ok P =>
    rw [he] at h
    have hsg : G1.inSubgroup P = true := by
      by_cases hs : G1.inSubgroup P = true
      · exact hs
      · simp [hs] at h
    have hi : (decodeLane inputs[l]).invalid = false := by
      cases hi : (decodeLane inputs[l]).invalid
      · rfl
      · exact False.elim (uncompress_of_invalid (invalid_undecided hi) hi P he)
    have hu' := hu
    rw [hf.undecided, hi, Bool.not_false, Bool.and_true,
      Bool.or_eq_false_iff, Bool.or_eq_false_iff] at hu'
    obtain ⟨⟨hdu, _⟩, hmu⟩ := hu'
    rw [uncompress_decoded hdu hi] at he
    have hroot : laneRoot inputs[l] ^ 2 = laneX inputs[l] ^ 2 * laneX inputs[l] + 4 := by
      by_contra hroot
      rw [if_neg hroot] at he
      cases he
    rw [if_pos hroot] at he
    have hp : lanePoint inputs[l] = P := Except.ok.inj he
    subst P
    have hm := (G1x8.scott_membership_iff (xOf inputs) (yOf inputs) l
      (laneX inputs[l]) (laneY inputs[l]) (lane_x inputs l) (lane_y inputs l)
      (lanePoint_valid hroot) hmu).mpr hsg
    change (membersOf inputs).members.toNat.testBit l = true at hm
    rw [hf.valid, decide_eq_true hroot, hm, hu, hi]
    rfl

theorem decompress_eq_spec (inputs : Vector Encoding 8) (l : Fin 8)
    (hu : (decompress inputs).undecided.toNat.testBit l = false) :
    laneVerdict (decompress inputs) l = G1Spec.verdict inputs[l] := by
  by_cases hv : (decompress inputs).valid.toNat.testBit l = true
  · obtain ⟨P, hP, hsg, hp, _⟩ := valid_sound inputs l hv
    rw [laneVerdict, if_pos hv, G1Spec.verdict_eq_decode, hP]
    simpa [hsg] using congrArg some hp
  · have hn : (G1Spec.verdict inputs[l]).isSome = false := by
      cases hs : (G1Spec.verdict inputs[l]).isSome
      · rfl
      · exact False.elim (hv (valid_complete inputs l hu hs))
    rw [laneVerdict, if_neg hv]
    cases he : G1Spec.verdict inputs[l] with
    | none => rfl
    | some p => rw [he] at hn; cases hn

theorem infinity_undecided (inputs : Vector Encoding 8) (l : Fin 8)
    (h : inputs[l] = G1Spec.infinity) :
    (decompress inputs).undecided.toNat.testBit l = true := by
  have hf := decompress_lane inputs l
  rw [hf.undecided, h]
  have hd : (decodeLane G1Spec.infinity).undecided = true ∧
      (decodeLane G1Spec.infinity).invalid = false := by decide +kernel
  rw [hd.1, hd.2]
  simp

end DecompressG1
end LeanBlsSimd
