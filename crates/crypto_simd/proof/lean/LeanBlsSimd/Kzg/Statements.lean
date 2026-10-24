import LeanBlsSimd.Portable.Fp.Correct
import LeanBlsSimd.Portable.Decode.Correct
import LeanBlsSimd.Kzg.Lincomb
import LeanBlsSimd.Kzg.CurveWorkConstruct
import LeanBlsSimd.Kzg.Setup
import LeanBlsSimd.Kzg.InterpolationKernel.Construct
import LeanBlsSimd.Kzg.Decoder
import LeanBlsSimd.Kzg.SpecBridge
import LeanBlsSimd.Kzg.Refines.Setup
import LeanBlsSimd.Kzg.Refines.Cosets
import LeanBlsSimd.Kzg.Refines.Verify
import LeanBlsSimd.Kzg.Refines.Pairing
import LeanBlsSimd.Kzg.ModelPairing
import LeanBlsSimd.Kzg.InterpolationIdentity
import LeanBlsSimd.Kzg.ModelSpec

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

structure Input where
  commitments : Slice (Aeneas.Std.Array U8 48#usize)
  indices : Slice U64
  cells : Slice (Aeneas.Std.Array U8 2048#usize)
  proofs : Slice (Aeneas.Std.Array U8 48#usize)

def Input.commitmentBytes (i : Input) : _root_.Array ByteArray :=
  (i.commitments.val.map arrayBytes).toArray
def Input.cellIndices (i : Input) : _root_.Array Nat := (i.indices.val.map (·.val)).toArray
def Input.cellBytes (i : Input) : _root_.Array ByteArray := (i.cells.val.map arrayBytes).toArray
def Input.proofBytes (i : Input) : _root_.Array ByteArray := (i.proofs.val.map arrayBytes).toArray

def Input.Representable (i : Input) : Prop :=
  i.commitments.val.length * 48 ≤ Isize.max.toNat ∧
  i.indices.val.length * 8 ≤ Isize.max.toNat ∧
  i.cells.val.length * 2048 ≤ Isize.max.toNat ∧
  i.proofs.val.length * 48 ≤ Isize.max.toNat

def Input.model (i : Input) : Bool :=
  Model.verify embeddedSetup i.commitmentBytes i.cellIndices i.cellBytes i.proofBytes

def Input.spec (i : Input) : KzgM Bool :=
  verifyCellKzgProofBatch i.commitmentBytes i.cellIndices i.cellBytes i.proofBytes

def Input.embeddedSpec (i : Input) : Except KzgError Bool :=
  Model.verifyPure embeddedSetup Model.specRli
    i.commitmentBytes i.cellIndices i.cellBytes i.proofBytes

def Input.generated [RuntimeFeatures] (i : Input) (v : verify.CellBatchVerifier) :=
  verify.CellBatchVerifier.verify v i.commitments i.indices i.cells i.proofs

theorem column_ifft_eq_interpolation
    (indices : _root_.Array Nat) (evals : _root_.Array (_root_.Array Fr))
    (powers : _root_.Array Fr) (h : Model.RliInputs indices evals powers) :
    Model.specRli indices evals powers = .ok (Model.columnRli indices evals powers) := by
  exact column_ifft_interpolation indices evals powers h

theorem spec_eq_column_ifft
    (cs : _root_.Array Bytes48) (indices : _root_.Array Nat)
    (cells : _root_.Array Cell) (ps : _root_.Array Bytes48) :
    verifyCellKzgProofBatch cs indices cells ps =
      Model.verifyWith (monadLift TrustedSetup.get!) Model.columnStep cs indices cells ps := by
  exact ModelSpec.upstream_spec_eq_column column_ifft_eq_interpolation cs indices cells ps

theorem model_eq_embedded_spec (i : Input) :
    Model.rejectErrors i.embeddedSpec = i.model := by
  exact ModelSpec.rejectErrors_spec_eq_model column_ifft_eq_interpolation embeddedSetup
    i.commitmentBytes i.cellIndices i.cellBytes i.proofBytes

theorem model_eq_spec (hsetup : TrustedSetup.get! = pure embeddedSetup) (i : Input) :
    (fun result => Model.rejectErrors result) <$> i.spec.run = pure i.model := by
  have hlift : (monadLift (pure embeddedSetup : IO TrustedSetup) : KzgM TrustedSetup) =
      pure embeddedSetup := rfl
  have hrun : i.spec.run = pure i.embeddedSpec := by
    rw [Input.spec, upstream_eq_verifyWith, hsetup, hlift, verifyWith_pure]
    rfl
  rw [hrun, ← model_eq_embedded_spec i]
  rfl

theorem setup_decode_refines [RuntimeFeatures] :
    ∃ s, setup.Setup.decode = ok s ∧ SetupRep s :=
  setup_decode_refinement

theorem cosets_new_refines :
    ∃ c, cosets.Cosets.new = ok c ∧ CosetsRep c :=
  cosets_new_refinement

theorem new_returns_ok_route [cpu : RuntimeFeatures] :
    ∃ v, verify.CellBatchVerifier.new = ok v ∧ StateInvariant v ∧
      CurveWork.isLanes v.curve_work = cpu.simdAvailable ∧
      v.kernel.isSome = cpu.simdAvailable := by
  obtain ⟨s, hs, hsrep⟩ := setup_decode_refines
  obtain ⟨c, hc, hcrep⟩ := cosets_new_refines
  obtain ⟨work, hw, hwork, hwroute⟩ := curveWork_new_refinement
  cases hsimd : cpu.simdAvailable with
  | false =>
    simp only [verify.CellBatchVerifier.new, hs, hc, ifma_available, hsimd,
      bind_tc_ok, Bool.false_eq_true, if_false,
      verify.Deduplicated.Insts.CoreDefaultDefault.default, hw]
    exact ⟨_, rfl, ⟨hsrep, hcrep, trivial, hwork⟩,
      by simpa only [hsimd] using hwroute, rfl⟩
  | true =>
    obtain ⟨kernel, hkernel, hki⟩ := InterpolationKernel.new_refinement c hcrep
    simp only [verify.CellBatchVerifier.new, hs, hc, ifma_available, hsimd,
      bind_tc_ok, if_true, hkernel,
      verify.Deduplicated.Insts.CoreDefaultDefault.default, hw]
    exact ⟨_, rfl, ⟨hsrep, hcrep, hki, hwork⟩,
      by simpa only [hsimd] using hwroute, rfl⟩

theorem new_returns_ok [cpu : RuntimeFeatures] :
    ∃ v, verify.CellBatchVerifier.new = ok v ∧ StateInvariant v := by
  obtain ⟨v, hnew, hinv, _, _⟩ := new_returns_ok_route
  exact ⟨v, hnew, hinv⟩

/-- Replacing work preserves the invariant when its persistent table is valid. -/
theorem stateInvariant_curveWork (v : verify.CellBatchVerifier) (work : verify.CurveWork)
    (hwork : CurveWorkInvariant work) (hv : StateInvariant v) :
    StateInvariant {v with curve_work := work} :=
  ⟨hv.1, hv.2.1, hv.2.2.1, hwork⟩

theorem stateInvariant_allows_scalar [RuntimeFeatures]
    (v : verify.CellBatchVerifier) (hv : StateInvariant v) :
    ∃ next, StateInvariant next ∧ next.kernel = v.kernel ∧
      CurveWork.isLanes next.curve_work = false := by
  obtain ⟨work, _, hwork, hroute⟩ := curveWork_portable_refinement
  exact ⟨{v with curve_work := work}, stateInvariant_curveWork v work hwork hv, rfl, hroute⟩

theorem default_eq_new [RuntimeFeatures] :
    verify.CellBatchVerifier.Insts.CoreDefaultDefault.default =
      verify.CellBatchVerifier.new := rfl

theorem glue_refinement [RuntimeFeatures] (h : ComponentContracts)
    (v : verify.CellBatchVerifier) (hv : StateInvariant v)
    (i : Input) (hi : i.Representable) :
    ∃ next, i.generated v = ok (i.model, next) ∧ StateInvariant next := by
  exact Verify.glue_of_contracts h (pairing_holds_refinement h) model_pairing_refinement
    v hv i.commitments i.indices i.cells i.proofs hi.2.2.1

theorem verify_eq_spec [cpu : RuntimeFeatures]
    (hmsm : PortableMsmCorrect) (hpairing : PairingCorrect) :
    ∃ initial, verify.CellBatchVerifier.new = ok initial ∧ StateInvariant initial ∧
      ∀ (v : verify.CellBatchVerifier), StateInvariant v →
      ∀ (i : Input), i.Representable →
      ∃ (verdict : Bool) (next : verify.CellBatchVerifier),
        i.generated v = ok (verdict, next) ∧ StateInvariant next ∧
        Model.rejectErrors i.embeddedSpec = verdict := by
  let h : ComponentContracts := ⟨hmsm, hpairing⟩
  obtain ⟨initial, hnew, hinv⟩ := new_returns_ok
  refine ⟨initial, hnew, hinv, fun v hv i hi => ?_⟩
  obtain ⟨next, hgen, hnext⟩ := glue_refinement h v hv i hi
  exact ⟨i.model, next, hgen, hnext, model_eq_embedded_spec i⟩

theorem verify_eq_upstream [cpu : RuntimeFeatures]
    (hmsm : PortableMsmCorrect) (hpairing : PairingCorrect)
    (hsetup : TrustedSetup.get! = pure embeddedSetup) :
    ∃ initial, verify.CellBatchVerifier.new = ok initial ∧ StateInvariant initial ∧
      ∀ (v : verify.CellBatchVerifier), StateInvariant v →
      ∀ (i : Input), i.Representable →
      ∃ (verdict : Bool) (next : verify.CellBatchVerifier),
        i.generated v = ok (verdict, next) ∧ StateInvariant next ∧
        (Model.rejectErrors <$> i.spec.run) = pure verdict := by
  obtain ⟨initial, hnew, hinv, hstep⟩ := verify_eq_spec hmsm hpairing
  refine ⟨initial, hnew, hinv, fun v hv i hi => ?_⟩
  obtain ⟨verdict, next, hgen, hnext, hverdict⟩ := hstep v hv i hi
  refine ⟨verdict, next, hgen, hnext, ?_⟩
  have hlift : (monadLift (pure embeddedSetup : IO TrustedSetup) : KzgM TrustedSetup) =
      pure embeddedSetup := rfl
  have hrun : i.spec.run = pure i.embeddedSpec := by
    rw [Input.spec, upstream_eq_verifyWith, hsetup, hlift, verifyWith_pure]
    rfl
  rw [hrun, ← hverdict]
  rfl

end LeanBlsSimd.Kzg
