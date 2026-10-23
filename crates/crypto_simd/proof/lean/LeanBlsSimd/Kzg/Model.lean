import EthLib.Cryptography.Kzg.Cells
import Batteries.Tactic.OpenPrivate

open EthLib.Cryptography Bls Kzg Kzg.Constants Kzg.BitReversal
open private cosetShiftForCell from EthLib.Cryptography.Kzg.Cells

namespace LeanBlsSimd.Kzg.Model

abbrev Front := Array KZGCommitment × Array Nat × Array CosetEvals × Array KZGProof
abbrev RliStep := Array Nat → Array (Array Fr) → Array Fr → Except KzgError (Array Fr)

def frontHalf
    (commitmentsBytes : Array Bytes48)
    (cellIndices : Array CellIndex)
    (cells : Array Cell)
    (proofsBytes : Array Bytes48) : Except KzgError Front := do

  if cells.size ≠ commitmentsBytes.size then
    throw (.inputLengthMismatch "cells" commitmentsBytes.size cells.size)
  if proofsBytes.size ≠ commitmentsBytes.size then
    throw (.inputLengthMismatch "proofsBytes" commitmentsBytes.size proofsBytes.size)
  if cellIndices.size ≠ commitmentsBytes.size then
    throw (.inputLengthMismatch "cellIndices" commitmentsBytes.size cellIndices.size)

  if let some cb := commitmentsBytes.find? (fun cb => cb.size != BYTES_PER_COMMITMENT) then
    throw (.badCommitmentSize cb.size)
  if cellIndices.any (· ≥ CELLS_PER_EXT_BLOB) then
    throw .cellIndexOutOfBounds
  if let some c := cells.find? (fun c => c.size != BYTES_PER_CELL) then
    throw (.badCellSize c.size)
  if let some pb := proofsBytes.find? (fun pb => pb.size != BYTES_PER_PROOF) then
    throw (.badProofSize pb.size)

  let (deduped, commitmentIndices) ←
    (Array.range commitmentsBytes.size).foldlM
      (init := ((#[] : Array KZGCommitment), (#[] : Array CommitmentIndex)))
      fun (deduped, commitmentIndices) i => do
        let cb := commitmentsBytes[i]!
        let _ ← match bytesToKzgCommitment cb with
                | .ok c    => pure c
                | .error _ => throw (.invalidCommitment (some i))
        match deduped.idxOf? cb with
        | some j => pure (deduped, commitmentIndices.push j)
        | none   => pure (deduped.push cb, commitmentIndices.push deduped.size)

  let cosetsEvals : Array CosetEvals ← cells.mapM fun c =>
    cellToCosetEvals c

  let proofs : Array KZGProof ← (Array.range proofsBytes.size).mapM fun i =>
    match bytesToKzgProof proofsBytes[i]! with
    | .ok p    => pure p
    | .error _ => throw (.invalidProof (some i))

  return (deduped, commitmentIndices, cosetsEvals, proofs)

def specRli (cellIndices : Array Nat) (cosetsEvals : Array (Array Fr))
    (rPowers : Array Fr) : Except KzgError (Array Fr) := do
  (Array.range cellIndices.size).foldlM
    (init := Array.replicate 64 Fr.zero)
    fun sumInterp k => do
      let interp ← interpolatePolynomialcoeff
        (← cosetForCell cellIndices[k]!) cosetsEvals[k]!
      let scaled ← multiplyPolynomialcoeff #[rPowers[k]!] interp
      pure (addPolynomialcoeff sumInterp scaled)

def columnRli (indices : Array Nat) (evals : Array (Array Fr)) (powers : Array Fr) : Array Fr :=
  (Array.range 128).foldl (init := Array.replicate 64 Fr.zero) fun total c =>
    let column := (Array.range indices.size).foldl (init := Array.replicate 64 Fr.zero)
      fun acc k => if indices[k]! = c then
        Array.ofFn (n := 64) (fun j => acc[j.val]! + powers[k]! * evals[k]![j.val]!)
      else acc
    let coeffs := fftField (bitReversalPermutation column) (computeRootsOfUnity 64) true
    let shift := (rootsOfUnityBrp 8192)[64*c]!
    addPolynomialcoeff total (shiftVals coeffs shift.inverse)

def columnStep : RliStep := fun indices evals powers => .ok (columnRli indices evals powers)

def RliInputs (indices : Array Nat) (evals : Array (Array Fr)) (powers : Array Fr) : Prop :=
  indices.size = evals.size ∧ indices.size = powers.size ∧
  (∀ i ∈ indices, i < 128) ∧ (∀ ys ∈ evals, ys.size = 64)

def lincomb
    (points : Array KZGCommitment) (scalars : Array Fr) : Except KzgError KZGCommitment := do
  if points.size ≠ scalars.size then
    throw (.lincombLengthMismatch points.size scalars.size)
  if points.size = 0 then
    return Bls.G1.compress Bls.G1.zero
  let pointsG1 ← points.mapM fun p =>
    match Bls.G1.uncompress p with
    | .ok g    => pure g
    | .error _ => throw KzgError.invalidG1Point
  return Bls.G1.compress (Bls.G1.msm pointsG1 scalars)


def implWith (getSetup : KzgM TrustedSetup) (rliStep : RliStep)
    (commitments : Array KZGCommitment)
    (commitmentIndices : Array CommitmentIndex)
    (cellIndices : Array CellIndex)
    (cosetsEvals : Array CosetEvals)
    (proofs : Array KZGProof) : KzgM Bool := do
  if cellIndices.size ≠ commitmentIndices.size then
    throw (.inputLengthMismatch "cellIndices" commitmentIndices.size cellIndices.size)
  if cosetsEvals.size ≠ commitmentIndices.size then
    throw (.inputLengthMismatch "cosetsEvals" commitmentIndices.size cosetsEvals.size)
  if proofs.size ≠ commitmentIndices.size then
    throw (.inputLengthMismatch "proofs" commitmentIndices.size proofs.size)
  if commitmentIndices.any (· ≥ commitments.size) then
    throw .commitmentIndexOutOfBounds
  if (Array.range commitments.size).any
      (fun i => commitments.idxOf? commitments[i]! ≠ some i) then
    throw .duplicateCommitments


  let setup ← getSetup
  let numCells := cellIndices.size
  let n := FIELD_ELEMENTS_PER_CELL
  let numCommitments := commitments.size

  let r := computeVerifyCellKzgProofBatchChallenge
            commitments commitmentIndices cellIndices cosetsEvals proofs
  let rPowers := computePowers r numCells

  let ll : G1 := (Bls.G1.uncompress (← g1Lincomb proofs rPowers)).toOption.get!

  let lr : G2 := setup.g2Monomial[n]!

  let weights : Array Fr := (Array.range numCells).foldl
    (init := Array.replicate numCommitments Fr.zero)
    fun weights k =>
      let i := commitmentIndices[k]!
      weights.set! i (weights[i]! + rPowers[k]!)

  let rlc : G1 := (Bls.G1.uncompress (← g1Lincomb commitments weights)).toOption.get!

  let sumInterp ← rliStep cellIndices cosetsEvals rPowers
  let rli : G1 := (Bls.G1.uncompress
                  (← g1Lincomb (setup.g1MonomialBytes.extract 0 n) sumInterp)).toOption.get!

  let weightedRPowers : Array Fr ← (Array.range numCells).mapM fun k => do
    let h_k ← cosetShiftForCell cellIndices[k]!
    pure (rPowers[k]! * (h_k ^ (Fr.ofNat n)))
  let rlp : G1 := (Bls.G1.uncompress (← g1Lincomb proofs weightedRPowers)).toOption.get!

  let rl : G1 := Bls.G1.add (Bls.G1.add rlc (Bls.G1.neg rli)) rlp

  return Bls.pairingCheck #[
    (ll, lr),
    (rl, Bls.G2.neg setup.g2Monomial[0]!)
  ]


def implPure (setup : TrustedSetup) (rliStep : RliStep)
    (commitments : Array KZGCommitment)
    (commitmentIndices : Array CommitmentIndex)
    (cellIndices : Array CellIndex)
    (cosetsEvals : Array CosetEvals)
    (proofs : Array KZGProof) : Except KzgError Bool := do
  if cellIndices.size ≠ commitmentIndices.size then
    throw (.inputLengthMismatch "cellIndices" commitmentIndices.size cellIndices.size)
  if cosetsEvals.size ≠ commitmentIndices.size then
    throw (.inputLengthMismatch "cosetsEvals" commitmentIndices.size cosetsEvals.size)
  if proofs.size ≠ commitmentIndices.size then
    throw (.inputLengthMismatch "proofs" commitmentIndices.size proofs.size)
  if commitmentIndices.any (· ≥ commitments.size) then
    throw .commitmentIndexOutOfBounds
  if (Array.range commitments.size).any
      (fun i => commitments.idxOf? commitments[i]! ≠ some i) then
    throw .duplicateCommitments


  let numCells := cellIndices.size
  let n := FIELD_ELEMENTS_PER_CELL
  let numCommitments := commitments.size

  let r := computeVerifyCellKzgProofBatchChallenge
            commitments commitmentIndices cellIndices cosetsEvals proofs
  let rPowers := computePowers r numCells

  let ll : G1 := (Bls.G1.uncompress (← lincomb proofs rPowers)).toOption.get!

  let lr : G2 := setup.g2Monomial[n]!

  let weights : Array Fr := (Array.range numCells).foldl
    (init := Array.replicate numCommitments Fr.zero)
    fun weights k =>
      let i := commitmentIndices[k]!
      weights.set! i (weights[i]! + rPowers[k]!)

  let rlc : G1 := (Bls.G1.uncompress (← lincomb commitments weights)).toOption.get!

  let sumInterp ← rliStep cellIndices cosetsEvals rPowers
  let rli : G1 := (Bls.G1.uncompress
                  (← lincomb (setup.g1MonomialBytes.extract 0 n) sumInterp)).toOption.get!

  let weightedRPowers : Array Fr ← (Array.range numCells).mapM fun k => do
    let h_k ← cosetShiftForCell cellIndices[k]!
    pure (rPowers[k]! * (h_k ^ (Fr.ofNat n)))
  let rlp : G1 := (Bls.G1.uncompress (← lincomb proofs weightedRPowers)).toOption.get!

  let rl : G1 := Bls.G1.add (Bls.G1.add rlc (Bls.G1.neg rli)) rlp

  return Bls.pairingCheck #[
    (ll, lr),
    (rl, Bls.G2.neg setup.g2Monomial[0]!)
  ]


def verifyWith (getSetup : KzgM TrustedSetup) (rli : RliStep)
    (cs : Array Bytes48) (indices : Array Nat) (cells : Array Cell) (ps : Array Bytes48) :
    KzgM Bool := do
  let (unique, ci, evals, proofs) ← frontHalf cs indices cells ps
  implWith getSetup rli unique ci indices evals proofs

def verifyPure (setup : TrustedSetup) (rli : RliStep)
    (cs : Array Bytes48) (indices : Array Nat) (cells : Array Cell) (ps : Array Bytes48) :
    Except KzgError Bool := do
  let (unique, ci, evals, proofs) ← frontHalf cs indices cells ps
  implPure setup rli unique ci indices evals proofs

def rejectErrors : Except KzgError Bool → Bool
  | .ok b => b
  | .error _ => false

def verify (setup : TrustedSetup)
    (cs : Array Bytes48) (indices : Array Nat) (cells : Array Cell) (ps : Array Bytes48) : Bool :=
  rejectErrors (verifyPure setup columnStep cs indices cells ps)

def deduplicate (cs : Array Bytes48) : Array Bytes48 × Array Nat :=
  cs.foldl (init := (#[], #[])) fun (unique, indices) c =>
    match unique.idxOf? c with
    | some i => (unique, indices.push i)
    | none => (unique.push c, indices.push unique.size)

def challengePreimage (unique : Array Bytes48) (ci indices : Array Nat)
    (cells : Array Cell) (ps : Array Bytes48) : ByteArray :=
  let header := RANDOM_CHALLENGE_KZG_CELL_BATCH_DOMAIN ++ intToBytesBE 4096 8 ++
    intToBytesBE 64 8 ++ intToBytesBE unique.size 8 ++ intToBytesBE indices.size 8
  let header := unique.foldl (init := header) (· ++ ·)
  (Array.range indices.size).foldl (init := header) fun b k =>
    b ++ intToBytesBE ci[k]! 8 ++ intToBytesBE indices[k]! 8 ++ cells[k]! ++ ps[k]!

def cosetShift (c : Nat) : Fr := (rootsOfUnityBrp 8192)[64*c]!
def roots (logOrder : Nat) : Array Fr := computeRootsOfUnity (2^logOrder)
def inverseRoots (rs : Array Fr) : Array Fr :=
  Array.ofFn (n := rs.size) fun i => if i.val = 0 then rs[0]! else rs[rs.size-i.val]!
def inverseFft (input rs : Array Fr) (scale : Fr) : Array Fr :=
  (fftFieldAux input rs).map (· * scale)

def pairingInputs (setup : TrustedSetup) (commitments proofs : Array G1)
    (commitmentIndices indices : Array Nat) (evals : Array CosetEvals) (r : Fr) :
    Array (G1 × G2) :=
  let powers := computePowers r indices.size
  let weights := (Array.range indices.size).foldl (init := Array.replicate commitments.size Fr.zero)
    fun weights k =>
      let i := commitmentIndices[k]!
      weights.set! i (weights[i]! + powers[k]!)
  let rlc := G1.msm commitments weights
  let monomial := (setup.g1MonomialBytes.extract 0 64).map
    (fun b => (G1.uncompress b).toOption.getD G1.zero)
  let rli := G1.msm monomial (columnRli indices evals powers)
  let shifted := (Array.range indices.size).map
    (fun k => powers[k]! * Fr.powNat (cosetShift indices[k]!) 64)
  let rlp := G1.msm proofs shifted
  #[(G1.msm proofs powers, setup.g2Monomial[64]!),
    (G1.add (G1.add rlc (G1.neg rli)) rlp, G2.neg setup.g2Monomial[0]!)]

end LeanBlsSimd.Kzg.Model
