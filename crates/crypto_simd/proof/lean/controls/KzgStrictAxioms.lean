import LeanBlsSimd.Axioms
import controls.KzgSpecInstance
import controls.KzgExternalBoundary
import controls.KzgMathematical
import controls.KzgSetupBoundary
import controls.ExtenderSpecInstance
import controls.ExtenderExternalBoundary
import controls.ExtenderMathematical
import controls.ExtenderLayout
import controls.ExtenderKernelBoundary
import controls.ExtenderKernelBytes
import controls.ExtenderKernelFft
import controls.ExtenderKernelTranspose
import controls.ExtenderKernelShortStage
import controls.ExtenderKernelLazy
import controls.ExtenderKernelRange
import controls.LeftShiftIntrinsic
import controls.Fr8Swap
import controls.Fr8Words
import controls.SignedLimbs

-- Check the proof, its concrete instance, and every negative control together.
#assert_standard_axioms
