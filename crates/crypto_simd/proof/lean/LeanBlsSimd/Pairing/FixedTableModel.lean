import LeanBlsSimd.Kzg.PairingTableBounds
import LeanBlsSimd.Kzg.SetupPoints
import LeanBlsSimd.Spec.Fp2Tower

open EthLib.Cryptography Bls

namespace LeanBlsSimd.Pairing

abbrev Affine := Fp2 × Fp2

def fixedPoint (pair : Fin 2) : Affine :=
  if pair = 0 then (Kzg.SetupPoints.g2Point64.x, Kzg.SetupPoints.g2Point64.y)
  else (Kzg.SetupPoints.g2Point0.x, -Kzg.SetupPoints.g2Point0.y)

/-- False doubles the running point; true adds the fixed point. -/
def lineKinds : Nat → List Bool
  | 0 => []
  | n + 1 => false :: ((if blsX.testBit n then [true] else []) ++ lineKinds n)

theorem lineKinds_length : (lineKinds 63).length = 68 := by decide +kernel

def lineKind (step : Fin 68) : Bool := (lineKinds 63)[step.val]!

def slopeDenominator (add : Bool) (q t : Affine) : Fp2 :=
  if add then q.1 - t.1 else t.2 + t.2

def slopeNumerator (add : Bool) (q t : Affine) : Fp2 :=
  if add then q.2 - t.2 else Fp2.ofFp (Fp.ofNat 3) * t.1 * t.1

def chord (t r : Affine) (slope : Fp2) : Affine :=
  let x := slope * slope - t.1 - r.1
  (x, slope * (t.1 - x) - t.2)

def onCurve (t : Affine) : Bool :=
  (t.2 * t.2).beq (t.1 * t.1 * t.1 + ⟨Fp.ofNat 4, Fp.ofNat 4⟩)

def encodedCoefficient (step : Fin 68) (pair coefficient : Fin 2) : Fp2 :=
  ⟨Fp.ofNat (Kzg.pairingRawValue (Kzg.pairingRaw step ⟨4 * pair.val + 2 * coefficient.val, by omega⟩)),
    Fp.ofNat (Kzg.pairingRawValue (Kzg.pairingRaw step ⟨4 * pair.val + 2 * coefficient.val + 1, by omega⟩))⟩

def coefficient (step : Fin 68) (pair i : Fin 2) : Fp2 :=
  ⟨Kzg.pairingLineValue step ⟨4 * pair.val + 2 * i.val, by omega⟩,
    Kzg.pairingLineValue step ⟨4 * pair.val + 2 * i.val + 1, by omega⟩⟩

def montgomery (a : Fp2) : Fp2 :=
  ⟨a.c0 * Fp.ofNat (2^416), a.c1 * Fp.ofNat (2^416)⟩

/-- Division-free certificates bind the fixed table to an affine Miller step. -/
def RowCertificate (step : Fin 68) (pair : Fin 2)
    (before after : Affine) (slope l1 l2 : Fp2) : Prop :=
  let q := fixedPoint pair
  let add := lineKind step
  let denominator := slopeDenominator add q before
  let c := slope * before.1 - before.2
  let next := chord before (if add then q else before) slope
  denominator.isZero = false ∧
  (slope * denominator).beq (slopeNumerator add q before) = true ∧
  after.1.beq next.1 = true ∧ after.2.beq next.2 = true ∧
  onCurve before = true ∧ onCurve after = true ∧
  c.isZero = false ∧ (l1 * c).beq (-slope) = true ∧
  (l2 * c).beq Fp2.one = true ∧
  (encodedCoefficient step pair 0).beq (montgomery l1) = true ∧
  (encodedCoefficient step pair 1).beq (montgomery l2) = true

end LeanBlsSimd.Pairing
