import LeanBlsSimd.Kzg.Extender.Kernel.FftShort

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg
open scoped EthLib.Cryptography.Bls.Fr

namespace LeanBlsSimd.Kzg.Extender.Controls.ShortRange

open Kernel

private def nearInput : fr8.Fr8 :=
  ⟨List.ofFn (fun j : Fin 5 => Vector.replicate 8
    (UInt64.ofNat ((2 * Fr.modulus - 1) / 2 ^ (52 * j.val) % 2 ^ 52))), by simp⟩

private theorem nearInput_valid :
    ShortInput true 1 nearInput (lazyLaneValue nearInput) := by
  refine ⟨?_, fun _ => rfl⟩
  unfold Lazy
  decide +kernel

private theorem nearInput_value :
    laneInt nearInput 0 = (2 : ℤ) * Fr.modulus - 1 := by decide +kernel

set_option linter.unreachableTactic false in
theorem dit_short_add_requires_full_class :
    ∃ out, fr8.Fr8.add_raw nearInput nearInput = ok out ∧
      ShortOutput true 1 out (fun lane => lazyLaneValue nearInput lane + lazyLaneValue nearInput lane) ∧
      ¬ LazyRep (4 * 1 - 1) (shortLimbBound (2 * 1)) out
        (fun lane => lazyLaneValue nearInput lane + lazyLaneValue nearInput lane) := by
  obtain ⟨out, hrun, hrep, hvalue⟩ := add_raw_lazy_refinement nearInput nearInput
    _ _ nearInput_valid nearInput_valid (by decide)
  have hfull : ShortOutput true 1 out
      (fun lane => lazyLaneValue nearInput lane + lazyLaneValue nearInput lane) :=
    hrep.mono (by omega) (by decide)
  fail_if_success
    have : LazyRep (4 * 1 - 1) (shortLimbBound (2 * 1)) out
        (fun lane => lazyLaneValue nearInput lane + lazyLaneValue nearInput lane) :=
      hrep.mono (by omega) (by decide)
  refine ⟨out, hrun, hfull, ?_⟩
  intro htight
  have hout := hvalue (0 : Fin 8)
  rw [nearInput_value] at hout
  have hbound := (htight.1 (0 : Fin 8)).2.1
  have hp : (2 : ℤ) < Fr.modulus := by decide +kernel
  norm_num only at hbound
  omega

#print axioms dit_short_add_requires_full_class

end LeanBlsSimd.Kzg.Extender.Controls.ShortRange
