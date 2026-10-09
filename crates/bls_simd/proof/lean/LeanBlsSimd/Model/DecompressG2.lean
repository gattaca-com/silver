import LeanBlsSimd.Model.G2x8

/-!
# `decompress_g2.rs`

`crates/bls_simd/src/decompress_g2.rs`, transcribed one statement per Rust statement. Each
96-byte encoding is a `Vector UInt8 96`, as Rust's `[u8; 96]`.

Rust's control flow maps as follows:

- The `for` loop of `decode` is a fold over the lanes; each `continue` ends that lane's step.
- The two early `return`s of `decompress` are `if … then batch else …`.
- `less_than_p` returns from inside its loop. Its fold carries `none` until a word differs, then
  the answer, which later words keep.
- `split_at`, `copy_from_slice` and `u64::from_be_bytes` are modelled by `split_at`, the index
  arithmetic of `fp_words`, and `u64_from_be_bytes`.

blst's `blst_fp`, `blst_fp2` and `blst_p2_affine` are structures over the same arrays; the
`Default` of `blst_p2_affine` is all zeros. The Rust module's items are in namespace
`DecompressG2`, as `decompress_g2::decompress` is in Rust.
-/

namespace LeanBlsSimd

namespace DecompressG2

def G2_COMPRESSED_LEN : ℕ := 96

def FP_BYTES : ℕ := G2_COMPRESSED_LEN / 2

def FLAG_COMPRESSED : UInt8 := 0x80

def FLAG_INFINITY : UInt8 := 0x40

def FLAG_LARGER_ROOT : UInt8 := 0x20

/-- `P_U64` as the `[u64; 6]` of `constants.rs`. -/
def P_U64v : Vector UInt64 6 := .ofFn fun w => .ofNat (P_U64.getD w 0)

structure BlstFp where
  l : Vector UInt64 6
deriving Inhabited

structure BlstFp2 where
  fp : Vector BlstFp 2
deriving Inhabited

/-- `blst_p2_affine`; its `Default` is all zeros, as `Inhabited` derives here. -/
structure BlstP2Affine where
  x : BlstFp2
  y : BlstFp2
deriving Inhabited

/-- Per-lane verdicts for one batch of eight. -/
structure Batch where
  points : Vector BlstP2Affine 8
  on_curve : Mmask8
  valid : Mmask8
  undecided : Mmask8

structure Decoded where
  x0 : Vector Limbs 8
  x1 : Vector Limbs 8
  larger_root : Mmask8
  invalid : Mmask8
  undecided : Mmask8

/-- `<[u8]>::split_at(FP_BYTES)` on 96 bytes. -/
def split_at (bytes : Vector UInt8 G2_COMPRESSED_LEN) : Vector UInt8 FP_BYTES × Vector UInt8 FP_BYTES :=
  (.ofFn fun i => bytes[i.val]'(by have := i.isLt; simp only [FP_BYTES, G2_COMPRESSED_LEN] at *; omega),
   .ofFn fun i => bytes[FP_BYTES + i.val]'(by
     have := i.isLt; simp only [FP_BYTES, G2_COMPRESSED_LEN] at *; omega))

/-- `u64::from_be_bytes`. -/
def u64_from_be_bytes (bytes : Vector UInt8 8) : UInt64 :=
  bytes.foldl (fun acc b => (acc <<< 8) ||| b.toUInt64) 0

/-- A 48-byte big-endian coordinate as little-endian 64-bit words. -/
def fp_words (be : Vector UInt8 FP_BYTES) : Vector UInt64 6 :=
  .ofFn fun w =>
    let bytes : Vector UInt8 8 := .ofFn fun i =>
      be[FP_BYTES - 8 * (w.val + 1) + i.val]'(by
        have := w.isLt; have := i.isLt; simp only [FP_BYTES, G2_COMPRESSED_LEN] at *; omega)
    u64_from_be_bytes bytes

def less_than_p (x : Vector UInt64 6) : Bool :=
  let r := (List.range 6).reverse.foldl (init := (none : Option Bool)) fun r w =>
    match r with
    | some b => some b
    | none => if x[w]! ≠ P_U64v[w]! then some (x[w]! < P_U64v[w]!) else none
  r.getD false

def decode (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) : Decoded :=
  let d : Decoded := {
    x0 := .replicate 8 (.replicate 8 0),
    x1 := .replicate 8 (.replicate 8 0),
    larger_root := 0,
    invalid := 0,
    undecided := 0 }
  (List.finRange 8).foldl (init := d) fun d (lane : Fin 8) =>
    let bytes := inputs[lane]
    let bit : Mmask8 := 1 <<< lane.val.toUInt8
    let flags := bytes[0]'(by simp [G2_COMPRESSED_LEN]) &&& 0xe0
    if flags &&& FLAG_COMPRESSED = 0 then { d with invalid := d.invalid ||| bit }
    else if flags &&& FLAG_INFINITY ≠ 0 then { d with undecided := d.undecided ||| bit }
    else
      let d := if flags &&& FLAG_LARGER_ROOT ≠ 0 then
        { d with larger_root := d.larger_root ||| bit } else d
      let (x1_bytes, x0_bytes) := split_at bytes
      let x1 := fp_words x1_bytes
      let x1 := x1.set 5 (x1[5] &&& 0x1fffffffffffffff)
      let x0 := fp_words x0_bytes
      if !less_than_p x1 || !less_than_p x0 then { d with invalid := d.invalid ||| bit }
      else { d with x0 := d.x0.set lane (unpack52 x0), x1 := d.x1.set lane (unpack52 x1) }

def decompress (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) : Batch :=
  let decoded := decode inputs
  let batch : Batch := {
    points := .replicate 8 default,
    on_curve := 0,
    valid := 0,
    undecided := decoded.undecided }
  let decodable := ~~~(decoded.invalid ||| decoded.undecided)
  if decodable = 0 then batch else

  let x : Fp2x8 := { c0 := Fp8.from_plain decoded.x0, c1 := Fp8.from_plain decoded.x1 }
  let four := Fp8.splat_limbs (.ofList FOUR_MONT)
  let rhs := (x.square.mul x).add { c0 := four, c1 := four }
  let (root, has_root) := rhs.sqrt
  let batch := { batch with on_curve := has_root &&& decodable }
  if batch.on_curve = 0 then batch else

  let flip := root.is_larger_root_mask ^^^ decoded.larger_root
  let y := Fp2x8.select flip root root.neg
  let membership := G2x8.scott_membership x y
  let batch := { batch with undecided := batch.undecided ||| (membership.undecided &&& batch.on_curve) }
  let batch := { batch with valid := membership.members &&& batch.on_curve &&& ~~~batch.undecided }

  let (x0, x1) := (x.c0.to_blst_limbs, x.c1.to_blst_limbs)
  let (y0, y1) := (y.c0.to_blst_limbs, y.c1.to_blst_limbs)
  (List.finRange 8).foldl (init := batch) fun batch (lane : Fin 8) =>
    { batch with points := batch.points.set lane {
        x := { fp := #v[{ l := x0[lane] }, { l := x1[lane] }] },
        y := { fp := #v[{ l := y0[lane] }, { l := y1[lane] }] } } }

end DecompressG2

end LeanBlsSimd
