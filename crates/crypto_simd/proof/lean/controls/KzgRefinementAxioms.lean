import LeanBlsSimd.Kzg.Refines
import LeanBlsSimd.Kzg.Refines.Checks
import LeanBlsSimd.Kzg.DedupModel
import LeanBlsSimd.Kzg.Refines.Interpolation
import LeanBlsSimd.Kzg.InterpolationModel
import LeanBlsSimd.Kzg.Refines.Frames
import LeanBlsSimd.Kzg.ModelFront
import LeanBlsSimd.Kzg.Refines.Verify
import LeanBlsSimd.Kzg.ModelPairingShift
import LeanBlsSimd.Kzg.G1Bridge

open Lean Elab Command

run_cmd do
  let allowed := [``propext, ``Classical.choice, ``Quot.sound]
  for c in #[``LeanBlsSimd.Kzg.same_bytes_refines, ``LeanBlsSimd.Kzg.reverse_bits_refines,
      ``LeanBlsSimd.Kzg.setup_decode_refines, ``LeanBlsSimd.Kzg.decode_points_refines,
      ``LeanBlsSimd.Kzg.roots_refines, ``LeanBlsSimd.Kzg.decode_cells_refines,
      ``LeanBlsSimd.Kzg.deduplicate_refines, ``LeanBlsSimd.Kzg.cosets_new_refines,
      ``LeanBlsSimd.Kzg.new_returns_ok, ``LeanBlsSimd.Kzg.challenge_preimage_eq_spec,
      ``LeanBlsSimd.Kzg.challenge_refines, ``LeanBlsSimd.Kzg.verify_indices_refinement,
      ``LeanBlsSimd.Kzg.verify_rejects_lengths, ``LeanBlsSimd.Kzg.model_rejects_lengths,
      ``LeanBlsSimd.Kzg.deduplicate_sizes, ``LeanBlsSimd.Kzg.deduplicate_mem,
      ``LeanBlsSimd.Kzg.deduplicate_indices, ``LeanBlsSimd.Kzg.deduplicate_nodup,
      ``LeanBlsSimd.Kzg.deduplicate_all,
      ``LeanBlsSimd.Kzg.Interpolation.aggregate_column,
      ``LeanBlsSimd.Kzg.Interpolation.aggregate_columns,
      ``LeanBlsSimd.Kzg.Interpolation.copy_column,
      ``LeanBlsSimd.Kzg.Interpolation.shift_add_loop,
      ``LeanBlsSimd.Kzg.inverse_fft_refines,
      ``LeanBlsSimd.Kzg.Interpolation.aggregate_columnRli,
      ``LeanBlsSimd.Kzg.interpolation_commitment_refines,
      ``LeanBlsSimd.Kzg.pairing_holds_refines,
      ``LeanBlsSimd.Kzg.decode_cells_frame,
      ``LeanBlsSimd.Kzg.ModelFront.frontHalf_option,
      ``LeanBlsSimd.Kzg.ModelFront.cell_decode_option,
      ``LeanBlsSimd.Kzg.ModelFront.cells_decode_option,
      ``LeanBlsSimd.Kzg.ModelFront.cells_values_flatten,
      ``LeanBlsSimd.Kzg.ModelFront.cells_values_size,
      ``LeanBlsSimd.Kzg.ModelFront.frontHalf_ok,
      ``LeanBlsSimd.Kzg.ModelFront.verify_of_front_none,
      ``LeanBlsSimd.Kzg.ModelFront.verify_of_bad_index,
      ``LeanBlsSimd.Kzg.Verify.glue_of_contracts,
      ``LeanBlsSimd.Kzg.ModelPairing.array_mapM_ok,
      ``LeanBlsSimd.Kzg.ModelPairing.cosetShift_eq,
      ``LeanBlsSimd.Kzg.ModelPairing.weighted_powers_eq,
      ``LeanBlsSimd.Kzg.model_pairing_refinement,
      ``LeanBlsSimd.Kzg.glue_refinement,
      ``LeanBlsSimd.Kzg.decoder_transport] do
    let axioms ← collectAxioms c
    unless axioms.all allowed.contains do
      throwError m!"{c} has unexpected axioms: {axioms.toList}"
    logInfo m!"{c}: {axioms.toList}"
