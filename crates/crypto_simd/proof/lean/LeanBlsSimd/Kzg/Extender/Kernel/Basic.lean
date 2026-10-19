import LeanBlsSimd.Kzg.Externals
import LeanBlsSimd.Kzg.Extender.Model

open Aeneas Aeneas.Std Result
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg
open scoped EthCryptographySpecs.Bls.Fr

attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero

namespace LeanBlsSimd.Kzg.Extender.Kernel

def laneNat (x : fr8.Fr8) (lane : Fin 8) : Nat :=
  ((List.finRange 5).map fun j =>
    (x.val[j.val]!)[lane].toNat * 2 ^ (52 * j.val)).sum

def Normalized (x : fr8.Fr8) : Prop :=
  ∀ (j : Fin 5) (lane : Fin 8), (x.val[j.val]!)[lane].toNat < 2 ^ 52

def Bounded (x : fr8.Fr8) : Prop :=
  Normalized x ∧ ∀ lane, laneNat x lane < 2 * Fr.modulus

def laneValue (x : fr8.Fr8) (lane : Fin 8) : Fr := Fr.ofNat (laneNat x lane)

def Represents (x : fr8.Fr8) (values : Fin 8 → Fr) : Prop :=
  Bounded x ∧ ∀ lane, laneValue x lane = values lane

/-- Ordinary data lanes represent plain integers; only multiplication constants carry R = 2^260. -/
def MultiplierRep (x : fr8.Fr8) (values : Fin 8 → Fr) : Prop :=
  Represents x (fun lane => values lane * Fr.ofNat (2 ^ 260))

def DataRep (data : Slice fr8.Fr8) (values : _root_.Array Fr) : Prop :=
  values.size = 8 * data.val.length ∧
    ∀ v : Fin data.val.length,
      Represents data.val[v.val] (fun lane => values[8 * v.val + lane.val]!)

def TransformSize (n : Nat) : Prop :=
  ∃ logSize : Nat, 4 ≤ logSize ∧ logSize ≤ 12 ∧ n = 2 ^ logSize

def sampleRoots (roots : _root_.Array Fr) (n : Nat) : _root_.Array Fr :=
  _root_.Array.ofFn (n := n) fun i => roots[i.val * (roots.size / n)]!

def RootsValid (roots : _root_.Array Fr) : Prop :=
  ∃ (omega : Fr) (k : Nat), roots.size = 2 ^ k ∧ IsPrimitiveRoot omega (2 ^ k) ∧
    ∀ i, i < roots.size → roots[i]! = omega ^ i

def FftInvariant (table : fft8.Fft8) (roots : _root_.Array Fr) : Prop :=
  TransformSize roots.size ∧ table.vectors.val = roots.size / 8 ∧
  table.wide.val.length = roots.size / 8 - 1 ∧
  (∀ stage : Nat, 3 ≤ stage → 2 ^ stage < roots.size →
    ∀ v : Fin (2 ^ stage / 8),
      MultiplierRep table.wide.val[2 ^ stage / 8 - 1 + v.val]!
        (fun lane => roots[(8 * v.val + lane.val) * (roots.size / (2 * 2 ^ stage))]!)) ∧
  MultiplierRep table.stage2 (fun lane => roots[(lane.val % 2) * (roots.size / 4)]!) ∧
  MultiplierRep table.stage4 (fun lane => roots[(lane.val % 4) * (roots.size / 8)]!)

def LanePairsInvariant (pairs : fft8.LanePairs) (h : Nat) : Prop :=
  (h = 1 ∨ h = 2 ∨ h = 4) ∧
  (∀ m : Fin 8,
    pairs.upper[m].toNat = m.val % 4 / h * (2 * h) + m.val % h + m.val / 4 * 8 ∧
    pairs.lower[m].toNat = m.val % 4 / h * (2 * h) + m.val % h + m.val / 4 * 8 + h) ∧
  (∀ e : Fin 8,
    pairs.first[e].toNat = e.val / (2 * h) * h + e.val % h +
      (if e.val % (2 * h) < h then 0 else 8) ∧
    pairs.second[e].toNat = e.val / (2 * h) * h + e.val % h + 4 +
      (if e.val % (2 * h) < h then 0 else 8))

def shiftFactor (i : Nat) : Fr :=
  (Kzg.Model.roots 13)[i]! * (Fr.ofNat 4096).inverse

/-- Rejected input may leave unbounded data lanes; the next decode overwrites all 512 vectors. -/
def StateInvariant (kernel : extension_kernel.ExtensionKernel) : Prop :=
  FftInvariant kernel.inverse (Kzg.Model.inverseRoots (Kzg.Model.roots 12)) ∧
  FftInvariant kernel.forward (Kzg.Model.roots 12) ∧
  kernel.shift.val.length = 512 ∧ kernel.data.val.length = 512 ∧
  ∀ v : Fin 512,
    MultiplierRep kernel.shift.val[v.val]! (fun lane => shiftFactor (8 * v.val + lane.val))

def SameTables (before after : extension_kernel.ExtensionKernel) : Prop :=
  after.inverse = before.inverse ∧ after.forward = before.forward ∧ after.shift = before.shift

end LeanBlsSimd.Kzg.Extender.Kernel
