import LeanBlsSimd.Proofs.G1Finite

namespace LeanBlsSimd.DecompressG1

open EthLib.Cryptography.Bls

/-- Field operations used by the decoder, before its membership test. -/
def xOf (inputs : Vector Encoding 8) : Fp8 := Fp8.from_plain (decode inputs).x

def rhsOf (inputs : Vector Encoding 8) : Fp8 :=
  ((xOf inputs).square.mul (xOf inputs)).add (Fp8.splat_limbs (.ofList FOUR_MONT))

def yOf (inputs : Vector Encoding 8) : Fp8 :=
  let root := (rhsOf inputs).sqrt_candidate
  Fp8.select (root.is_larger_root_mask ^^^ (decode inputs).larger_root) root root.neg

def membersOf (inputs : Vector Encoding 8) : Membership :=
  G1x8.scott_membership (xOf inputs) (yOf inputs)

theorem lane_x (inputs : Vector Encoding 8) (l : Fin 8) :
    (xOf inputs).Holds l (laneX inputs[l]) := by
  have hd := decode_holds inputs l
  exact (Fp8.holds_from_plain hd.inv).of_eq (by rw [hd.val]; rfl)

theorem lane_rhs (inputs : Vector Encoding 8) (l : Fin 8) :
    (rhsOf inputs).Holds l (laneX inputs[l] ^ 2 * laneX inputs[l] + 4) := by
  have hx := lane_x inputs l
  have h4 := (Fp8.holds_splat_limbs inv_ofList_FOUR_MONT l).of_eq decode_ofList_FOUR_MONT
  exact (hx.square.mul hx).add h4

theorem lane_y (inputs : Vector Encoding 8) (l : Fin 8) :
    (yOf inputs).Holds l (laneY inputs[l]) := by
  have hr := (lane_rhs inputs l).sqrt_candidate
  have hd := decode_holds inputs l
  exact (hr.select _ hr.neg).of_eq (by
    rw [Mmask8.testBit_xor, hr.testBit_is_larger_root_mask, hd.largerRoot]
    rfl)

private theorem points_get (f : Fin 8 → BlstP1Affine) (l : Fin 8) :
    ∀ (ls : List (Fin 8)) (v : Vector BlstP1Affine 8),
    (ls.foldl (fun v i => v.set i (f i)) v)[l] = if l ∈ ls then f l else v[l]
  | [], v => by simp
  | i :: ls, v => by
    rw [List.foldl_cons, points_get f l ls]
    by_cases hlr : l ∈ ls
    · simp [hlr]
    · by_cases hli : l = i
      · subst hli; simp
      · have hi : (i : ℕ) ≠ l := fun h => hli (Fin.ext h).symm
        simp [hlr, hli, Vector.getElem_set_ne _ _ hi]

structure LaneFacts (inputs : Vector Encoding 8) (l : Fin 8) : Prop where
  undecided : (decompress inputs).undecided.toNat.testBit l =
    (((decodeLane inputs[l]).undecided || decide (laneY inputs[l] = 0) ||
      (membersOf inputs).undecided.toNat.testBit l) && !(decodeLane inputs[l]).invalid)
  valid : (decompress inputs).valid.toNat.testBit l =
    (decide (laneRoot inputs[l] ^ 2 = laneX inputs[l] ^ 2 * laneX inputs[l] + 4) &&
      (membersOf inputs).members.toNat.testBit l &&
      !(decompress inputs).undecided.toNat.testBit l && !(decodeLane inputs[l]).invalid)
  points : (decompress inputs).points[l] = G1Spec.blstLimbs (lanePoint inputs[l])

theorem decompress_lane (inputs : Vector Encoding 8) (l : Fin 8) : LaneFacts inputs l := by
  have hx := lane_x inputs l
  have hy := lane_y inputs l
  have hr := (lane_rhs inputs l).sqrt_candidate
  have hd := decode_holds inputs l
  constructor
  · change (((decode inputs).undecided ||| (yOf inputs).is_zero_mask |||
      (membersOf inputs).undecided) &&& ~~~(decode inputs).invalid).toNat.testBit l = _
    rw [Mmask8.testBit_and, Mmask8.testBit_not, Mmask8.testBit_or, Mmask8.testBit_or,
      hd.invalid, hd.undecided, hy.testBit_is_zero_mask]
  · change (((rhsOf inputs).sqrt_candidate.square.eq_mask (rhsOf inputs)) &&&
      (membersOf inputs).members &&& ~~~(decompress inputs).undecided &&&
      ~~~(decode inputs).invalid).toNat.testBit l = _
    rw [Mmask8.testBit_and, Mmask8.testBit_and, Mmask8.testBit_and,
      Mmask8.testBit_not, Mmask8.testBit_not, hd.invalid,
      hr.square.testBit_eq_mask (lane_rhs inputs l)]
    rfl
  · change ((List.finRange 8).foldl (fun (v : Vector BlstP1Affine 8) (i : Fin 8) => v.set i
      (point (xOf inputs).to_blst_limbs[i] (yOf inputs).to_blst_limbs[i]))
      (.replicate 8 default))[l] = _
    rw [points_get, if_pos (List.mem_finRange l), blstLimbs_lanePoint]
    unfold point
    rw [DecompressG2.blstFp_eq hx.val64_to_blst_limbs,
      DecompressG2.blstFp_eq hy.val64_to_blst_limbs]

end LeanBlsSimd.DecompressG1
