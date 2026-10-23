import LeanBlsSimd.Kzg.SetupLiterals
import LeanBlsSimd.Refines.Word64

open LeanBlsSimd.Word64 LeanBlsSimd.Kzg
open silver_crypto_simd

namespace LeanBlsSimd.Controls.SetupLiterals

set_option maxRecDepth 16000
set_option exponentiation.threshold 512

private def y0 (p : blst.blst_p2_affine) : Int :=
  value (p.y.fp.val[0]'(by rw [p.y.fp.property]; decide)).l

theorem wrong_generator_sign_rejected :
    Kzg.SetupLiterals.g2_neg_generator ≠ g2Affine SetupPoints.g2Point0 := by
  intro h
  have hv := congrArg y0 h
  have hn : y0 Kzg.SetupLiterals.g2_neg_generator ≠
      y0 (g2Affine SetupPoints.g2Point0) := by decide +kernel
  exact hn hv

end LeanBlsSimd.Controls.SetupLiterals
