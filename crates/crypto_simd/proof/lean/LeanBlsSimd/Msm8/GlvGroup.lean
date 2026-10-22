import LeanBlsSimd.Model.Glv
import LeanBlsSimd.Spec.G1Curve

namespace LeanBlsSimd.G1Spec
open EthCryptographySpecs.Bls

theorem sigma_eq_lambda_smul (P : E.Point) (hP : Fr.modulus • P = 0) :
    sigma P = Glv.lambda • P := by
  have h := sigma_polynomial P
  rw [scott_complete P hP] at h
  apply eq_of_sub_eq_zero
  calc
    sigma P - Glv.lambda • P = P + sigma P + (-(z ^ 2)) • P := by
      rw [Glv.lambda_eq, sub_smul, one_smul, neg_smul]
      abel
    _ = 0 := h

theorem glv_decomposition_smul (P : E.Point) (hP : Fr.modulus • P = 0) (k : ℤ) :
    Glv.first k • P + Glv.second k • sigma P = k • P := by
  have hr : Glv.modulus • P = 0 := by simpa [Glv.modulus_eq] using hP
  calc
    Glv.first k • P + Glv.second k • sigma P =
        (Glv.first k + Glv.lambda * Glv.second k) • P := by
      rw [sigma_eq_lambda_smul P hP]
      module
    _ = k • P := by
      rw [Glv.decomposition, sub_smul, mul_smul, hr, zsmul_zero, sub_zero]

end LeanBlsSimd.G1Spec
