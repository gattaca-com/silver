import LeanBlsSimd.Kzg.Extender.Kernel.Fr8
import LeanBlsSimd.Kzg.Extender.Kernel.Lazy
import LeanBlsSimd.Kzg.Extender.Decode

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls Kzg
open scoped EthLib.Cryptography.Bls.Fr
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel

def DataRepWith (rep : fr8.Fr8 → (Fin 8 → Fr) → Prop)
    (data : Slice fr8.Fr8) (values : _root_.Array Fr) : Prop :=
  values.size = 8 * data.val.length ∧
    ∀ v : Fin data.val.length,
      rep data.val[v.val] (fun lane => values[8 * v.val + lane.val]!)

theorem transpose_representation (data : Slice fr8.Fr8) (offset : Usize)
    (values : Fin 8 → Fin 8 → Fr) (hsize : offset.val + 8 ≤ data.val.length)
    (hvalues : ∀ row, Represents data.val[offset.val + row.val]! (values row)) :
    ∃ out, fr8.Fr8.transpose data offset = ok out ∧
      ∀ row, Represents out.val[row.val]! (fun lane => values lane row) := by
  obtain ⟨out, hout, hlimb⟩ := transpose_refinement data offset hsize
  have hnat (row lane : Fin 8) :
      laneNat out.val[row.val]! lane = laneNat data.val[offset.val + lane.val]! row := by
    unfold laneNat
    simp_rw [hlimb]
  refine ⟨out, hout, ?_⟩
  intro row
  refine ⟨⟨?_, ?_⟩, ?_⟩
  · intro j lane
    rw [hlimb]
    exact (hvalues lane).1.1 j row
  · intro lane
    rw [hnat]
    exact (hvalues lane).1.2 row
  · intro lane
    simpa only [laneValue, hnat] using (hvalues lane).2 row

theorem lazy_transpose_representation (k m : Nat)
    (data : Slice fr8.Fr8) (offset : Usize)
    (values : Fin 8 → Fin 8 → Fr) (hsize : offset.val + 8 ≤ data.val.length)
    (hvalues : ∀ row, LazyRep k m data.val[offset.val + row.val]! (values row)) :
    ∃ out, fr8.Fr8.transpose data offset = ok out ∧
      ∀ row, LazyRep k m out.val[row.val]! (fun lane => values lane row) := by
  obtain ⟨out, hout, hlimb⟩ := transpose_refinement data offset hsize
  have hint (row lane : Fin 8) :
      laneInt out.val[row.val]! lane = laneInt data.val[offset.val + lane.val]! row := by
    unfold laneInt
    simp_rw [hlimb]
  refine ⟨out, hout, ?_⟩
  intro row
  refine ⟨?_, ?_⟩
  · intro lane
    refine ⟨?_, ?_, ?_⟩
    · rw [hint]
      exact ((hvalues lane).1 row).1
    · rw [hint]
      exact ((hvalues lane).1 row).2.1
    · intro j
      rw [hlimb]
      exact ((hvalues lane).1 row).2.2 j
  · intro lane
    simpa only [lazyLaneValue, hint] using (hvalues lane).2 row

theorem add_representation (a b : fr8.Fr8) (av bv : Fin 8 → Fr)
    (ha : Represents a av) (hb : Represents b bv) :
    ∃ out, fr8.Fr8.add a b = ok out ∧ Represents out (fun lane => av lane + bv lane) := by
  obtain ⟨out, hout, hbound, hv⟩ := add_refinement a b ha.1 hb.1
  exact ⟨out, hout, hbound, fun lane => (hv lane).2.trans (by rw [ha.2, hb.2])⟩

theorem sub_representation (a b : fr8.Fr8) (av bv : Fin 8 → Fr)
    (ha : Represents a av) (hb : Represents b bv) :
    ∃ out, fr8.Fr8.sub a b = ok out ∧ Represents out (fun lane => av lane - bv lane) := by
  obtain ⟨out, hout, hbound, hv⟩ := sub_refinement a b ha.1 hb.1
  exact ⟨out, hout, hbound, fun lane => (hv lane).2.trans (by rw [ha.2, hb.2])⟩

end LeanBlsSimd.Kzg.Extender.Kernel
