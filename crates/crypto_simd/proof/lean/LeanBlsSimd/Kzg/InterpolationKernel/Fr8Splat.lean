import LeanBlsSimd.Kzg.Extender.Kernel.Fr8

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel

theorem splat_multiplier_refinement (w : Fr) :
    ∃ out, fr8.Fr8.splat (frEncode (w * Fr.ofNat 16)) = ok out ∧
      MultiplierRep out (fun _ => w) := by
  let input := Array.to_slice (Array.repeat 8#usize (frEncode (w * Fr.ofNat 16)))
  obtain ⟨out, hout, hrep⟩ := load_multiplier_refinement input 0#usize (fun _ => w)
    (by simp [input, Array.to_slice, Array.repeat])
    (by intro lane; fin_cases lane <;> simp [input, Array.to_slice, Array.repeat])
  refine ⟨out, ?_, hrep⟩
  rw [BytePacking.load_refines input 0#usize
    (by simp [input, Array.to_slice, Array.repeat])] at hout
  have heq : fr8.Fr8.splat (frEncode (w * Fr.ofNat 16)) =
      ok (toArray id (BytePacking.transpose (BytePacking.loadedLanes input 0#usize))) := by
    simp only [fr8.Fr8.splat, BytePacking.unpack_refines, bind_tc_ok,
      FrModel.Simd.splat_limbs_refines]
    congr 2
  exact heq.trans hout

end LeanBlsSimd.Kzg.Extender.Kernel
