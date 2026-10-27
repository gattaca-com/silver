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

/-- Curve work contains only scratch buffers; both routes accept arbitrary contents. -/
def CurveWorkInvariant (_work : verify.CurveWork) : Prop := True

theorem curveWorkInvariant_sum [RuntimeFeatures]
    (work next : verify.CurveWork) (ps : Slice blst.blst_p1_affine)
    (fs : Slice blst.blst_fr) (point : blst.blst_p1)
    (_hcall : work.sum ps fs = ok (point, next)) (_h : CurveWorkInvariant work) :
    CurveWorkInvariant next := trivial

end LeanBlsSimd.Kzg
