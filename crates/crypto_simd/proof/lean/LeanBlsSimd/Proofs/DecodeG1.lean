import LeanBlsSimd.Model.DecompressG1
import LeanBlsSimd.Proofs.Decode

namespace LeanBlsSimd.DecompressG1

open EthLib.Cryptography.Bls
open DecompressG2 (FP_BYTES fp_words flag_compressed flag_infinity flag_larger_root inv_replicate_zero)

/-- What `decode` records for one lane's bytes, with its x coordinate as an integer. -/
structure LaneDecode where
  x : ℕ
  largerRoot : Bool
  invalid : Bool
  undecided : Bool

/-- `decode` on one lane's bytes, in the spec's terms: the flags of byte 0, and x
as a big-endian integer with its flag bits cleared. -/
def decodeLane (bytes : Encoding) : LaneDecode :=
  let head := bytes[0]
  let v := bytesVal (clearFlags bytes).toList
  if head &&& 0x80 = 0 then ⟨0, false, true, false⟩
  else if head &&& 0x40 ≠ 0 then ⟨0, false, false, true⟩
  else if v < Fp.modulus then ⟨v, decide (head &&& 0x20 ≠ 0), false, false⟩
  else ⟨0, decide (head &&& 0x20 ≠ 0), true, false⟩

/-- Lane `l` of `d` holds `r`: limbs that meet `Fp8Inv` with `r`'s values, and `r`'s mask bits. -/
structure LaneDecode.Holds (r : LaneDecode) (d : Decoded) (l : Fin 8) : Prop where
  inv : Fp8Inv d.x[l]
  val : val d.x[l] = r.x
  largerRoot : d.larger_root.toNat.testBit l = r.largerRoot
  invalid : d.invalid.toNat.testBit l = r.invalid
  undecided : d.undecided.toNat.testBit l = r.undecided

/-- Lane `l` of a `Decoded`: its limbs and its three mask bits. -/
def Decoded.lane (d : Decoded) (l : Fin 8) : Limbs × Bool × Bool × Bool :=
  (d.x[l], d.larger_root.toNat.testBit l, d.invalid.toNat.testBit l,
    d.undecided.toNat.testBit l)

theorem LaneDecode.Holds.of_lane {r : LaneDecode} {d d' : Decoded} {l : Fin 8} (h : r.Holds d l)
    (he : d'.lane l = d.lane l) : r.Holds d' l := by
  simp only [Decoded.lane, Prod.mk.injEq] at he
  obtain ⟨h0, h1, h2, h3⟩ := he
  exact ⟨h0 ▸ h.inv, h0 ▸ h.val, h1 ▸ h.largerRoot, h2 ▸ h.invalid, h3 ▸ h.undecided⟩

theorem decodeStep_lane_ne (inputs : Vector (Encoding) 8) (d : Decoded)
    {i l : Fin 8} (hl : l ≠ i) : (decodeStep inputs d i).lane l = d.lane l := by
  have hb (k : Mmask8) : (k ||| (1 <<< i.val.toUInt8)).toNat.testBit l = k.toNat.testBit l := by
    rw [Mmask8.testBit_or, Mmask8.testBit_one_shiftLeft, decide_eq_false hl, Bool.or_false]
  have hs (v : Vector Limbs 8) (x : Limbs) : (v.set i x)[l] = v[l] :=
    Vector.getElem_set_ne _ _ (fun h => hl (Fin.ext h).symm)
  unfold decodeStep
  dsimp only
  split_ifs <;> simp only [Decoded.lane, hb, hs]

def initLane : Limbs × Bool × Bool × Bool :=
  (.replicate 8 0, false, false, false)

theorem decodeStep_lane_self (inputs : Vector (Encoding) 8) (d : Decoded)
    (i : Fin 8) (h0 : d.lane i = initLane) :
    (decodeLane inputs[i]).Holds (decodeStep inputs d i) i := by
  simp only [Decoded.lane, initLane, Prod.mk.injEq] at h0
  obtain ⟨hx, hlr, hinv, hund⟩ := h0
  have hb (k : Mmask8) : (k ||| (1 <<< i.val.toUInt8)).toNat.testBit i = true := by
    rw [Mmask8.testBit_or, Mmask8.testBit_one_shiftLeft, decide_eq_true rfl, Bool.or_true]
  unfold decodeStep decodeLane
  dsimp only
  simp only [flag_compressed, flag_infinity, flag_larger_root]
  rw [fp_words_clear_flags, less_than_p_iff, val64_fp_words]
  have hz : Fp8Inv d.x[i] ∧ val d.x[i] = 0 :=
    ⟨hx ▸ inv_replicate_zero, by rw [hx]; exact val_replicate_zero⟩
  have hcond (p : Prop) [Decidable p] : ((!decide p) = true) = ¬p := by
    by_cases h : p <;> simp [h]
  simp only [hcond, ite_not]
  generalize inputs[i][0] = head
  have hok {v : Vector UInt8 FP_BYTES} (h : bytesVal v.toList < Fp.modulus) :
      Fp8Inv (unpack52 (fp_words v)) ∧ val (unpack52 (fp_words v)) = bytesVal v.toList := by
    rw [← val64_fp_words] at h ⊢
    exact ⟨inv_unpack52 h, (unpack52_spec _).2⟩
  have hs (v : Vector Limbs 8) (x : Limbs) : (v.set i x)[i] = x := Vector.getElem_set_self ..
  split_ifs with h1 h2 h3 h4
  · exact ⟨hz.1, hz.2, hlr, hb _, hund⟩
  · refine ⟨?_, ?_, ?_, hinv, hund⟩
    · rw [hs]; exact (hok h3).1
    · rw [hs]; exact (hok h3).2
    · rw [hlr, decide_eq_false (not_not.mpr h4)]
  · refine ⟨?_, ?_, ?_, hinv, hund⟩
    · rw [hs]; exact (hok h3).1
    · rw [hs]; exact (hok h3).2
    · rw [hb, decide_eq_true h4]
  · exact ⟨hz.1, hz.2, by rw [hlr, decide_eq_false (not_not.mpr ‹_›)], hb _, hund⟩
  · exact ⟨hz.1, hz.2, by rw [hb, decide_eq_true ‹_›], hb _, hund⟩
  · exact ⟨hz.1, hz.2, hlr, hinv, hb _⟩

theorem foldl_decodeStep (inputs : Vector (Encoding) 8) :
    ∀ (ls : List (Fin 8)) (d : Decoded) (l : Fin 8), ls.Nodup →
      (l ∉ ls → (ls.foldl (decodeStep inputs) d).lane l = d.lane l) ∧
      (l ∈ ls → d.lane l = initLane →
        (decodeLane inputs[l]).Holds (ls.foldl (decodeStep inputs) d) l)
  | [], d, l, _ => ⟨fun _ => rfl, fun h => absurd h List.not_mem_nil⟩
  | i :: ls, d, l, hnd => by
    have hi : i ∉ ls := (List.nodup_cons.mp hnd).1
    have hnd' := (List.nodup_cons.mp hnd).2
    rw [List.foldl_cons]
    refine ⟨fun hl => ?_, fun hl h0 => ?_⟩
    · have hli : l ≠ i := fun h => hl (h ▸ List.mem_cons_self ..)
      have hlr : l ∉ ls := fun h => hl (List.mem_cons_of_mem _ h)
      rw [(foldl_decodeStep inputs ls _ l hnd').1 hlr, decodeStep_lane_ne inputs d hli]
    · by_cases hli : l = i
      · subst hli
        exact (decodeStep_lane_self inputs d l h0).of_lane
          ((foldl_decodeStep inputs ls _ l hnd').1 hi)
      · have hlr : l ∈ ls := (List.mem_cons.mp hl).resolve_left hli
        exact (foldl_decodeStep inputs ls _ l hnd').2 hlr
          (by rw [decodeStep_lane_ne inputs d hli, h0])

/-- Each lane of `decode` records what its own bytes decode to. -/
theorem decode_holds (inputs : Vector (Encoding) 8) (l : Fin 8) :
    (decodeLane inputs[l]).Holds (decode inputs) l := by
  refine (foldl_decodeStep inputs _ decodeInit l (List.nodup_finRange 8)).2
    (List.mem_finRange l) ?_
  simp [Decoded.lane, decodeInit, initLane]

end LeanBlsSimd.DecompressG1
