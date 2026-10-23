import LeanBlsSimd.Kzg.PortableFp
import LeanBlsSimd.Kzg.CurveWorkState

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg

/-- Decode a lane of the fixed table from its radix-2^52, Montgomery-2^416 form. -/
def pairingLineValue (step : Fin 68) (lane : Fin 8) : Fp :=
  let row := pairing_lines.PAIRING_LINES.val[step.val]'(by simpa using step.isLt)
  let raw := row.val[lane.val]'(by simpa using lane.isLt)
  Fp.ofNat (raw.val.foldr (fun word acc => word.val + 2^52 * acc) 0) *
    (Fp.ofNat (2^416)).inverse

/-- Every stored coefficient is canonical and represents the corresponding
coefficient of the fixed extracted table after changing the Montgomery radix. -/
def PortableLinesRep (lines : portable.pairing.PairingLines) : Prop :=
  ∀ (step : Fin 68) (pair coefficient : Fin 2),
    let row := lines.val[step.val]'(by simpa using step.isLt)
    let pairLines := row.val[pair.val]'(by simpa using pair.isLt)
    let value := pairLines.val[coefficient.val]'(by simpa using coefficient.isLt)
    PortableFpRep value.c0
      (pairingLineValue step ⟨4 * pair.val + 2 * coefficient.val, by omega⟩) ∧
    PortableFpRep value.c1
      (pairingLineValue step ⟨4 * pair.val + 2 * coefficient.val + 1, by omega⟩)

def CurveWorkInvariant (work : verify.CurveWork) : Prop :=
  match CurveWork.pairingLines work with
  | none => True
  | some lines => PortableLinesRep lines

theorem curveWorkInvariant_of_table_eq {work next : verify.CurveWork}
    (he : CurveWork.pairingLines next = CurveWork.pairingLines work)
    (h : CurveWorkInvariant work) : CurveWorkInvariant next := by
  simpa only [CurveWorkInvariant, he] using h

theorem curveWorkInvariant_sum [RuntimeFeatures]
    (work next : verify.CurveWork) (ps : Slice blst.blst_p1_affine)
    (fs : Slice blst.blst_fr) (point : blst.blst_p1)
    (hcall : work.sum ps fs = ok (point, next)) (h : CurveWorkInvariant work) :
    CurveWorkInvariant next :=
  curveWorkInvariant_of_table_eq (CurveWork.sum_frame work next ps fs point hcall).2 h

end LeanBlsSimd.Kzg
