import LeanBlsSimd.Kzg.Extender.Kernel.Fr8
import LeanBlsSimd.Kzg.Extender.Decode

open Aeneas Aeneas.Std Result
open EthCryptographySpecs Bls Kzg
open scoped EthCryptographySpecs.Bls.Fr
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel

def permuted (a b : Fin 8 → Fr) (index : M512) (lane : Fin 8) : Fr :=
  let source : Fin 8 := ⟨index[lane].toNat % 8, Nat.mod_lt _ (by decide)⟩
  if index[lane].toNat.testBit 3 then b source else a source

theorem permute_representation (a b : fr8.Fr8) (av bv : Fin 8 → Fr) (index : M512)
    (ha : Represents a av) (hb : Represents b bv) :
    ∃ out, fr8.Fr8.permute a index b = ok out ∧ Represents out (permuted av bv index) := by
  obtain ⟨out, hout, hp, hbound⟩ := permute_refinement a b index
  refine ⟨out, hout, hbound ha.1 hb.1, ?_⟩
  intro lane
  let source : Fin 8 := ⟨index[lane].toNat % 8, Nat.mod_lt _ (by decide)⟩
  have hval : laneNat out lane = if index[lane].toNat.testBit 3 then
      laneNat b source else laneNat a source := by
    unfold laneNat
    simp_rw [hp]
    cases index[lane].toNat.testBit 3 <;> rfl
  simp only [laneValue, hval, permuted]
  split
  · exact hb.2 source
  · exact ha.2 source

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
