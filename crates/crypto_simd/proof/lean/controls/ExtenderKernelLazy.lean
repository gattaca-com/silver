import LeanBlsSimd.Kzg.Extender.Kernel.Fr8AddSub
import LeanBlsSimd.Proofs.Fr8Product

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg
open scoped EthLib.Cryptography.Bls.Fr

namespace LeanBlsSimd.Kzg.Extender.Controls.LazyArithmetic

open Kernel

def addWithReduction (reduce : Bool) (a b : fr8.Fr8) : Result fr8.Fr8 := do
  let raw ← fr8.Fr8.add_raw a b
  let normal ← fr8.Fr8.normalise raw
  if reduce then fr8.Fr8.reduced normal else ok normal

example : addWithReduction true = fr8.Fr8.add := rfl

theorem missing_reduction_breaks_output_bound :
    ∃ input good bad,
      Represents input (fun _ => 0) ∧
      addWithReduction true input input = ok good ∧ Bounded good ∧
      addWithReduction false input input = ok bad ∧ ¬ Bounded bad := by
  obtain ⟨input, _, hn, hv⟩ := multiple_of_r_refinement 1#u64 (by decide)
  have hv' (lane : Fin 8) : laneNat input lane = Fr.modulus := by simpa using hv lane
  have hi : Represents input (fun _ => 0) := by
    refine ⟨⟨hn, fun lane => ?_⟩, fun lane => ?_⟩
    · rw [hv']
      have := Fr.modulus_pos
      omega
    · simp only [laneValue, hv', Fr.ofNat_eq_natCast]
      change (Fr.modulus : ZMod Fr.modulus) = 0
      exact ZMod.natCast_self Fr.modulus
  obtain ⟨good, hg, hgood⟩ := add_lazy_representation input input _ _ hi.lazy hi.lazy
    (by decide) (by decide)
  obtain ⟨raw, hr, hraw, hre⟩ := add_raw_lazy_refinement input input _ _ hi.lazy hi.lazy
    (by decide)
  obtain ⟨bad, hb, hnorm, hbe⟩ := normalise_lazy_refinement raw _ hraw (by decide) (by decide)
  refine ⟨input, good, bad, hi, ?_, hgood.1, ?_, ?_⟩
  · change fr8.Fr8.add input input = ok good
    exact hg
  · simp only [addWithReduction, hr, hb, bind_tc_ok, Bool.false_eq_true, if_false]
  · intro hbad
    have he := (hbe (0 : Fin 8)).1
    rw [hre, laneInt_eq_laneNat hn, hv'] at he
    have hlt := hbad.2 (0 : Fin 8)
    omega

private def limbsOfNat (n : Nat) : FrModel.Limbs :=
  Vector.ofFn fun j => UInt64.ofNat (n / 2 ^ (52 * j.val) % 2 ^ 52)

theorem canonical_multiplier_bound_is_needed :
    let a := limbsOfNat (31 * Fr.modulus + 1)
    let w := limbsOfNat (FrModel.R % Fr.modulus + Fr.modulus)
    (∀ j : Fin FrModel.LIMBS, a[j].toNat < 2^52) ∧
    (∀ j : Fin FrModel.LIMBS, w[j].toNat < 2^52) ∧
    FrModel.val a < 32 * Fr.modulus ∧ FrModel.val w < 2 * Fr.modulus ∧
    FrModel.val w % Fr.modulus = FrModel.R % Fr.modulus ∧
    FrModel.val (FrModel.Lane.mulRaw a w) = 2 * Fr.modulus + 1 := by
  decide +kernel

example : (34 : ℤ) * Fr.modulus < (2 : ℤ)^260 := by decide +kernel
example : ¬ ((36 : ℤ) * Fr.modulus < (2 : ℤ)^260) := by decide +kernel
example : (370 : ℤ) * 2^52 < (2 : ℤ)^62 := by decide +kernel

end LeanBlsSimd.Kzg.Extender.Controls.LazyArithmetic
