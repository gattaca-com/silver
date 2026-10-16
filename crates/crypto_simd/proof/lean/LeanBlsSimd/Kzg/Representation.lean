import LeanBlsSimd.Extracted.FunsExternal
import EthCryptographySpecs.Kzg.Cells

open Aeneas.Std
open EthCryptographySpecs Bls
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

def bytes (xs : List U8) : ByteArray := ⟨(xs.map (fun x => UInt8.ofBitVec x.bv)).toArray⟩
def arrayBytes {n : Usize} (xs : Aeneas.Std.Array U8 n) : ByteArray := bytes xs.val

def limbs (xs : List U64) : Nat :=
  xs.foldr (fun x acc => x.val + 2^64 * acc) 0

def words (n : Usize) (x : Nat) : Aeneas.Std.Array U64 n :=
  ⟨(List.range n.val).map (fun i => ⟨BitVec.ofNat 64 (x / 2^(64*i))⟩), by simp⟩

def frEncode (x : Fr) : blst.blst_fr := ⟨words 4#usize ((x.val * 2^256) % Fr.modulus)⟩
def frRead (x : blst.blst_fr) : Fr := Fr.ofNat (limbs x.l.val) * (Fr.ofNat (2^256)).inverse
def fpEncode (x : Fp) : blst.blst_fp := ⟨words 6#usize ((x.val * 2^384) % Fp.modulus)⟩
def fpRead (x : blst.blst_fp) : Fp := Fp.ofNat (limbs x.l.val) * (Fp.ofNat (2^384)).inverse

def fp2Encode (x : Fp2) : blst.blst_fp2 :=
  ⟨⟨[fpEncode x.c0, fpEncode x.c1], by simp⟩⟩

def fp2Read (x : blst.blst_fp2) : Fp2 :=
  ⟨fpRead x.fp.val[0], fpRead x.fp.val[1]⟩

def g1Affine (p : G1) : blst.blst_p1_affine :=
  ⟨fpEncode p.toAffine.1, fpEncode p.toAffine.2⟩

def g2Affine (p : G2) : blst.blst_p2_affine :=
  ⟨fp2Encode p.toAffine.1, fp2Encode p.toAffine.2⟩

def g1ReadAffine (p : blst.blst_p1_affine) : G1 :=
  let x := fpRead p.x
  let y := fpRead p.y
  if x.isZero && y.isZero then G1.zero else ⟨x, y, Fp.one⟩

def g2ReadAffine (p : blst.blst_p2_affine) : G2 :=
  let x := fp2Read p.x
  let y := fp2Read p.y
  if x.isZero && y.isZero then G2.zero else ⟨x, y, Fp2.one⟩

def g1Jacobian (p : G1) : blst.blst_p1 := ⟨fpEncode p.x, fpEncode p.y, fpEncode p.z⟩
def g1ReadJacobian (p : blst.blst_p1) : G1 := ⟨fpRead p.x, fpRead p.y, fpRead p.z⟩

def FpReduced (x : blst.blst_fp) : Prop := limbs x.l.val < Fp.modulus
def FrReduced (x : blst.blst_fr) : Prop := limbs x.l.val < Fr.modulus
def JacobianReduced (p : blst.blst_p1) : Prop :=
  FpReduced p.x ∧ FpReduced p.y ∧ FpReduced p.z

def G1Valid (p : G1) : Prop :=
  (p.isInfinity = true ∨
    p.toAffine.2 * p.toAffine.2 = p.toAffine.1 * p.toAffine.1 * p.toAffine.1 + Fp.ofNat 4) ∧
  p.inSubgroup = true

def G1Rep (p : blst.blst_p1) (q : G1) : Prop :=
  JacobianReduced p ∧ (g1ReadJacobian p).isInfinity = q.isInfinity ∧
    (g1ReadJacobian p).toAffine = q.toAffine

def G1AffineValid (p : blst.blst_p1_affine) : Prop :=
  p = g1Affine (g1ReadAffine p) ∧ G1Valid (g1ReadAffine p)

def G2AffineValid (p : blst.blst_p2_affine) : Prop :=
  p = g2Affine (g2ReadAffine p) ∧
    ∃ b, G2.uncompress b = .ok (g2ReadAffine p) ∧ (g2ReadAffine p).inSubgroup = true

def specPoint (b : ByteArray) : Option G1 :=
  (Kzg.bytesToKzgProof b).toOption.bind (fun validated => (G1.uncompress validated).toOption)

def specVerdict (b : Aeneas.Std.Array U8 48#usize) : Option blst.blst_p1_affine :=
  (specPoint (arrayBytes b)).map g1Affine

def specG2Verdict (b : Aeneas.Std.Array U8 96#usize) : Option blst.blst_p2_affine :=
  (G2.uncompress (arrayBytes b)).toOption.bind
    (fun p => if p.inSubgroup then some (g2Affine p) else none)

end LeanBlsSimd.Kzg
