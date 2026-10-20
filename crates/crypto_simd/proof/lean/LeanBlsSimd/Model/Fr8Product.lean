import LeanBlsSimd.Model.Fr8

namespace LeanBlsSimd.FrModel

/-- The five surviving accumulator limbs before carry propagation. -/
def Lane.mulRaw (a b : Limbs) : Limbs :=
  .ofFn fun j => (Lane.mulAcc a b)[LIMBS + j.val]

def Fr8.mulRaw (a b : Fr8) : Fr8 :=
  Fr8.ofLanes (.ofFn fun l => Lane.mulRaw (a.lane l) (b.lane l))

end LeanBlsSimd.FrModel
