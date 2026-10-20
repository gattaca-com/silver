import LeanBlsSimd.Proofs.EarlyCarry
import LeanBlsSimd.Model.Fr8

namespace LeanBlsSimd

example (t : UInt64) :
    srli 52 (madd52lo t (Limbs.ofList P)[0] (madd52lo 0 t (.ofNat P_INV52))) =
      srli 52 (t + UInt64.ofNat MASK52) := by
  exact Lane.carry_of_cleared_eq t _ _ (by decide)

example (t : UInt64) :
    srli 52 (madd52lo t (FrModel.Limbs.ofList FrModel.P)[0]
      (madd52lo 0 t (.ofNat FrModel.P_INV52))) =
      srli 52 (t + UInt64.ofNat MASK52) := by
  exact Lane.carry_of_cleared_eq t _ _ (by decide)

example : srli 52 (madd52lo 1 (Limbs.ofList P)[0]
    (madd52lo 0 1 (.ofNat P_INV52))) ≠ srli 52 1 := by
  decide

example : srli 52 (madd52lo 1 (Limbs.ofList P)[0]
    (madd52lo 0 1 (.ofNat P_INV52))) ≠
      srli 52 (1 + UInt64.ofNat (MASK52 - 1)) := by
  decide

example : srli 52 (madd52lo 1 (FrModel.Limbs.ofList FrModel.P)[0]
    (madd52lo 0 1 (.ofNat FrModel.P_INV52))) ≠ srli 52 1 := by
  decide

example : srli 52 (madd52lo 1 (FrModel.Limbs.ofList FrModel.P)[0]
    (madd52lo 0 1 (.ofNat FrModel.P_INV52))) ≠
      srli 52 (1 + UInt64.ofNat (MASK52 - 1)) := by
  decide

example : (srli 52 (UInt64.ofNat (2^64 - 1) + UInt64.ofNat MASK52)).toNat ≠
    ((2^64 - 1) + MASK52) / 2^52 := by
  decide

#print axioms Lane.carry_of_cleared_eq

end LeanBlsSimd
