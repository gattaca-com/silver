import LeanBlsSimd.Kzg.Representation
import LeanBlsSimd.Extracted.Funs

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd

namespace LeanBlsSimd.Kzg

/-- The generated portable MSM consumes canonical ordinary scalar words and
valid reduced affine points, for arbitrary reusable scratch. -/
structure PortableMsmCorrect [RuntimeFeatures] : Prop where
  msm : ∀ (state : portable.msm.Msm) (ps : Slice blst.blst_p1_affine)
    (ws : Slice (Aeneas.Std.Array U64 4#usize)),
    ps.val.length = ws.val.length → (∀ p ∈ ps.val, G1AffineValid p) →
    (∀ w ∈ ws.val, limbs w.val < Fr.modulus) →
    ∃ point state', state.msm ps ws = ok (point, state') ∧
      G1Rep point (G1.msm (ps.val.map g1ReadAffine).toArray
        (ws.val.map (fun w => Fr.ofNat (limbs w.val))).toArray)

end LeanBlsSimd.Kzg
