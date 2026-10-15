import LeanBlsSimd.Model.G1x8
import LeanBlsSimd.Model.DecompressG2

namespace LeanBlsSimd.DecompressG1

open DecompressG2 (BlstFp FLAG_COMPRESSED FLAG_INFINITY FLAG_LARGER_ROOT fp_words less_than_p)

abbrev Encoding := Vector UInt8 48

structure BlstP1Affine where
  x : BlstFp
  y : BlstFp
deriving Inhabited

structure Batch where
  points : Vector BlstP1Affine 8
  valid : Mmask8
  undecided : Mmask8

structure Decoded where
  x : Vector Limbs 8
  larger_root : Mmask8
  invalid : Mmask8
  undecided : Mmask8

def decodeInit : Decoded := ⟨.replicate 8 (.replicate 8 0), 0, 0, 0⟩

def decodeStep (inputs : Vector Encoding 8) (d : Decoded) (lane : Fin 8) : Decoded :=
  let bytes := inputs[lane]
  let bit : Mmask8 := 1 <<< lane.val.toUInt8
  let flags := bytes[0] &&& 0xe0
  if flags &&& FLAG_COMPRESSED = 0 then { d with invalid := d.invalid ||| bit }
  else if flags &&& FLAG_INFINITY ≠ 0 then { d with undecided := d.undecided ||| bit }
  else
    let d := if flags &&& FLAG_LARGER_ROOT ≠ 0 then
      { d with larger_root := d.larger_root ||| bit } else d
    let words := fp_words bytes
    let words := words.set 5 (words[5] &&& 0x1fffffffffffffff)
    if !less_than_p words then { d with invalid := d.invalid ||| bit }
    else { d with x := d.x.set lane (unpack52 words) }

def decode (inputs : Vector Encoding 8) : Decoded :=
  (List.finRange 8).foldl (decodeStep inputs) decodeInit

def point (x y : Vector UInt64 6) : BlstP1Affine := ⟨⟨x⟩, ⟨y⟩⟩

def decompress (inputs : Vector Encoding 8) : Batch :=
  let decoded := decode inputs
  let x := Fp8.from_plain decoded.x
  let rhs := (x.square.mul x).add (Fp8.splat_limbs (.ofList FOUR_MONT))
  let root := rhs.sqrt_candidate
  let on_curve := root.square.eq_mask rhs
  let flip := root.is_larger_root_mask ^^^ decoded.larger_root
  let y := Fp8.select flip root root.neg
  let undecided := decoded.undecided ||| y.is_zero_mask
  let membership := G1x8.scott_membership x y
  let undecided := (undecided ||| membership.undecided) &&& ~~~decoded.invalid
  let valid := on_curve &&& membership.members &&& ~~~undecided &&& ~~~decoded.invalid
  let xs := x.to_blst_limbs
  let ys := y.to_blst_limbs
  let points := (List.finRange 8).foldl
    (fun points lane => points.set lane (point xs[lane] ys[lane])) (.replicate 8 default)
  ⟨points, valid, undecided⟩

def laneVerdict (batch : Batch) (lane : Fin 8) : Option BlstP1Affine :=
  if batch.valid.toNat.testBit lane then some batch.points[lane] else none

end LeanBlsSimd.DecompressG1
