import LeanBlsSimd.Kzg.SetupValidity
import LeanBlsSimd.Kzg.G1Arithmetic
import LeanBlsSimd.Kzg.G1Msm
import LeanBlsSimd.Kzg.G1Compression
import LeanBlsSimd.Kzg.PairingRepresentation
import LeanBlsSimd.Kzg.PairingInputs
import LeanBlsSimd.Kzg.PortableG1
import LeanBlsSimd.Kzg.Lincomb

open Lean Elab Command

run_cmd do
  let allowed := [``propext, ``Classical.choice, ``Quot.sound]
  for c in #[``LeanBlsSimd.Kzg.frEncode_reduced, ``LeanBlsSimd.Kzg.fpEncode_reduced,
      ``LeanBlsSimd.Kzg.frRead_frEncode, ``LeanBlsSimd.Kzg.fpRead_fpEncode,
      ``LeanBlsSimd.Kzg.fp2Read_fp2Encode, ``LeanBlsSimd.Kzg.g1Jacobian_rep,
      ``LeanBlsSimd.Kzg.setup_g1_roundtrip,
      ``LeanBlsSimd.Kzg.setup_g1_valid, ``LeanBlsSimd.Kzg.setup_g1_affine_valid,
      ``LeanBlsSimd.Kzg.setup_g2_cell_valid, ``LeanBlsSimd.Kzg.setup_g2_neg_zero_valid,
      ``LeanBlsSimd.Kzg.g1Valid_transport, ``LeanBlsSimd.Kzg.g1Valid_of_rep,
      ``LeanBlsSimd.Kzg.g1ReadAffine_g1Affine_matches, ``LeanBlsSimd.Kzg.g1Affine_valid,
      ``LeanBlsSimd.Kzg.g1Valid_zero, ``LeanBlsSimd.Kzg.g1Valid_neg, ``LeanBlsSimd.Kzg.g1Valid_add,
      ``LeanBlsSimd.Kzg.g1Valid_double, ``LeanBlsSimd.Kzg.g1Valid_mulNat, ``LeanBlsSimd.Kzg.g1Valid_mul,
      ``LeanBlsSimd.Kzg.g1_toPoint_eq_iff, ``LeanBlsSimd.Kzg.g1_toPoint_mulNat,
      ``LeanBlsSimd.Kzg.g1_neg_matches, ``LeanBlsSimd.Kzg.g1_add_matches,
      ``LeanBlsSimd.Kzg.g1_msm_spec, ``LeanBlsSimd.Kzg.g1Valid_msm,
      ``LeanBlsSimd.Kzg.g1_msm_congr, ``LeanBlsSimd.Kzg.g1_msm_rep,
      ``LeanBlsSimd.Kzg.g1_uncompress_infinity, ``LeanBlsSimd.Kzg.g1_uncompress_curve,
      ``LeanBlsSimd.Kzg.g1_uncompress_compress, ``LeanBlsSimd.Kzg.validateKzgG1_facts,
      ``LeanBlsSimd.Kzg.specPoint_isSome, ``LeanBlsSimd.Kzg.specPoint_uncompress,
      ``LeanBlsSimd.Kzg.specPoint_valid,
      ``LeanBlsSimd.Kzg.embedded_ofG1_eq, ``LeanBlsSimd.Kzg.pairingCheck_two_congr,
      ``LeanBlsSimd.Kzg.g1Rep_trans, ``LeanBlsSimd.Kzg.g1_msm_valid_of_mem,
      ``LeanBlsSimd.Kzg.verify_lincomb_refinement, ``LeanBlsSimd.Kzg.PortableG1.neg_refines,
      ``LeanBlsSimd.Kzg.PortableG1.add_complete_refines, ``LeanBlsSimd.Kzg.setup_model_points_eq,
      ``LeanBlsSimd.Kzg.setup_model_points_valid, ``LeanBlsSimd.Kzg.curveWork_pairing_check_refinement,
      ``LeanBlsSimd.Kzg.PortableG1.from_blst_refines,
      ``LeanBlsSimd.Kzg.portableFpRep_zero, ``LeanBlsSimd.Kzg.portableFpRep_one,
      ``LeanBlsSimd.Kzg.PortableFpCorrect.square, ``LeanBlsSimd.Kzg.PortableFpCorrect.neg,
      ``LeanBlsSimd.Kzg.pairing_points_in_lanes_refinement,
      ``LeanBlsSimd.Kzg.pairing_points_refinement,
      ``LeanBlsSimd.Kzg.curveWorkInvariant_of_table_eq,
      ``LeanBlsSimd.Kzg.curveWorkInvariant_sum] do
    let axioms ← collectAxioms c
    unless axioms.all allowed.contains do
      throwError m!"{c} has unexpected axioms: {axioms.toList}"
    logInfo m!"{c}: {axioms.toList}"
