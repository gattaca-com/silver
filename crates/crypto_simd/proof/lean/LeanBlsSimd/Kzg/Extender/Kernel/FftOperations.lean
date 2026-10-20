import LeanBlsSimd.Kzg.Extender.Kernel.Fr8
import LeanBlsSimd.Kzg.Extender.Decode

open Aeneas Aeneas.Std Result
open EthCryptographySpecs Bls Kzg
open scoped EthCryptographySpecs.Bls.Fr
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel

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
