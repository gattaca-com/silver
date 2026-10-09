import LeanBlsSimd.Model.DecompressG2

/-!
# Differential test of `DecompressG2.decompress` against the Rust

`lake exe differential <file>` runs the Lean model of `decompress_g2::decompress` on every batch
of a vector file and compares its result with the one the Rust returned, field by field. The
file is `../decompress_g2_vectors.txt`, written by `../vectors.rs`. The
model is a hand transcription of the Rust. The proofs concern the model, so this test is the
evidence that the model computes what the Rust computes, on the inputs in the file.

The exit status is 0 when every batch matches, 1 when any value differs, and 2 when the file
cannot be read or is malformed or incomplete: a missing header or `endfile` line, no batch, a
batch count that differs from the header's, batch indices that are not 0, 1, 2, ... in order, or
any line that breaks the format. A mismatch prints the batch, its kind, the lane, the field and
both values.

## File format

Text, one item per line. A line starting with `#` is a comment and is ignored. The file is a
header, the batches, and a last line `endfile`:

```
seed <seed>          the seed of the generator that chose the inputs
batches <n>          the number of batches that follow; at least 1
```

A batch is

```
batch <index> <kind>
in <192 hex digits>          eight lines, the 96 bytes of lane 0 to 7
on_curve <2 hex digits>      the three masks; bit l is lane l
valid <2 hex digits>
undecided <2 hex digits>
pt <lane> <24 hex words>     eight lines, lanes 0 to 7
end
```

Batch indices run 0 to n - 1 in file order. The 24 words of `pt` are the `u64` limbs of
`blst_p2_affine`: `x.fp[0].l`, `x.fp[1].l`, `y.fp[0].l`, `y.fp[1].l`, six limbs each, least
significant first. Words are lower-case hex
without leading zeros. The `pt` lines carry every lane's `points`, including lanes that are not
on the curve, where the Rust leaves the zero point or the coordinates it computed anyway.

`<kind>` names how the batch was built and is reported in mismatches.
-/

open LeanBlsSimd LeanBlsSimd.DecompressG2

namespace DifferentialTest

structure Header where
  seed : String
  count : Nat

structure Expected where
  index : Nat
  kind : String
  inputs : Array (Array UInt8)
  onCurve : UInt8
  valid : UInt8
  undecided : UInt8
  points : Array (Array UInt64)

def hexDigit? (c : Char) : Option Nat :=
  if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else none

def hexNat? (s : String) : Option Nat :=
  if s.isEmpty then none
  else s.foldl (fun acc c => do let a ← acc; let d ← hexDigit? c; pure (a * 16 + d)) (some 0)

def hexBytes? (s : String) : Option (Array UInt8) := do
  guard (s.length % 2 = 0)
  let cs := s.toList.toArray
  (Array.range (s.length / 2)).mapM fun i => do
    let hi ← hexDigit? cs[2 * i]!
    let lo ← hexDigit? cs[2 * i + 1]!
    pure (UInt8.ofNat (hi * 16 + lo))

def showHex (n : Nat) : String := String.ofList (Nat.toDigits 16 n)

def showMask (m : UInt8) : String :=
  let s := showHex m.toNat
  (if s.length < 2 then "0" else "") ++ s

def words (line : String) : List String :=
  (line.splitOn " ").filter (· ≠ "")

/-- The meaningful lines of the file, each with its 1-based line number. -/
def meaningful (text : String) : Array (Nat × String) :=
  let numbered := (text.splitOn "\n").toArray.mapIdx fun i l => (i + 1, l.trimAscii.toString)
  numbered.filter fun (_, l) => !l.isEmpty && !l.startsWith "#"

abbrev Parser := StateT (Array (Nat × String)) (Except String)

def next : Parser (Nat × String) := do
  let lines ← get
  match lines[0]? with
  | none => throw "unexpected end of file"
  | some l => set (lines.extract 1 lines.size); pure l

def peek : Parser (Nat × String) := do
  let lines ← get
  match lines[0]? with
  | none => throw "unexpected end of file"
  | some l => pure l

def headerLine (name : String) : Parser String := do
  let (n, l) ← next
  match words l with
  | [k, v] => if k = name then pure v else throw s!"line {n}: expected `{name} <value>`"
  | _ => throw s!"line {n}: expected `{name} <value>`"

def header : Parser Header := do
  let seed ← headerLine "seed"
  let countText ← headerLine "batches"
  match countText.toNat? with
  | some count => pure { seed, count }
  | none => throw s!"bad batch count `{countText}`"

def field (name : String) (digits : Nat) : Parser (Nat × String) := do
  let (n, l) ← next
  match words l with
  | [k, v] =>
    if k = name && v.length = digits then pure (n, v)
    else throw s!"line {n}: expected `{name}` with {digits} hex digits"
  | _ => throw s!"line {n}: expected `{name}` with {digits} hex digits"

def maskField (name : String) : Parser UInt8 := do
  let (n, v) ← field name 2
  match hexNat? v with
  | some m => pure (UInt8.ofNat m)
  | none => throw s!"line {n}: bad hex in `{name}`"

def inputLine : Parser (Array UInt8) := do
  let (n, v) ← field "in" 192
  match hexBytes? v with
  | some b => pure b
  | none => throw s!"line {n}: bad hex in `in`"

def pointLine (lane : Nat) : Parser (Array UInt64) := do
  let (n, l) ← next
  match words l with
  | "pt" :: laneStr :: rest =>
    if laneStr ≠ toString lane || rest.length ≠ 24 then
      throw s!"line {n}: expected `pt {lane}` with 24 words"
    let ws ← rest.toArray.mapM fun w => match hexNat? w with
      | some v => if v < 2 ^ 64 then pure (UInt64.ofNat v) else throw s!"line {n}: word out of range"
      | none => throw s!"line {n}: bad hex word `{w}`"
    pure ws
  | _ => throw s!"line {n}: expected `pt {lane}` with 24 words"

def batch : Parser Expected := do
  let (n, l) ← next
  let (index, kind) ← match words l with
    | ["batch", i, k] => match i.toNat? with
      | some i => pure (i, k)
      | none => throw s!"line {n}: bad batch index"
    | _ => throw s!"line {n}: expected `batch <index> <kind>`"
  let inputs ← (Array.range 8).mapM fun _ => inputLine
  let onCurve ← maskField "on_curve"
  let valid ← maskField "valid"
  let undecided ← maskField "undecided"
  let points ← (Array.range 8).mapM pointLine
  let (n, l) ← next
  if l ≠ "end" then throw s!"line {n}: expected `end`"
  pure { index, kind, inputs, onCurve, valid, undecided, points }

partial def batches : Parser (Array Expected) := do
  let (_, l) ← peek
  if l = "endfile" then
    let _ ← next
    pure #[]
  else
    let b ← batch
    let rest ← batches
    pure (#[b] ++ rest)

def file : Parser (Header × Array Expected) := do
  let h ← header
  let bs ← batches
  let rest ← get
  if let some (n, _) := rest[0]? then throw s!"line {n}: text after `endfile`"
  if bs.isEmpty then throw "no batches"
  if bs.size ≠ h.count then
    throw s!"header says {h.count} batches, the file holds {bs.size}"
  for (b, i) in bs.toList.zipIdx do
    if b.index ≠ i then throw s!"batch {b.index} where batch {i} was expected"
  pure (h, bs)

def parse (text : String) : Except String (Header × Array Expected) :=
  (file.run (meaningful text)).map (·.1)

/-- The model's input type from eight 96-byte arrays. -/
def modelInputs (inputs : Array (Array UInt8)) : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8 :=
  .ofFn fun l => .ofFn fun j => (inputs[l.val]!)[j.val]!

def fpLimbs (fp : BlstFp) : List UInt64 := fp.l.toList

/-- The 24 limbs of a point in the file's order. -/
def pointWords (p : BlstP2Affine) : Array UInt64 :=
  (fpLimbs p.x.fp[0] ++ fpLimbs p.x.fp[1] ++ fpLimbs p.y.fp[0] ++ fpLimbs p.y.fp[1]).toArray

def fpName (w : Nat) : String :=
  s!"{if w / 12 = 0 then "x" else "y"}.fp[{w / 6 % 2}].l[{w % 6}]"

structure Tally where
  batches : Nat := 0
  lanes : Nat := 0
  masks : Nat := 0
  limbs : Nat := 0
  mismatches : Nat := 0

def maxPrinted : Nat := 40

def report (t : Tally) (e : Expected) (lane : Option Nat) (field : String) (rust lean : String) :
    IO Tally := do
  if t.mismatches < maxPrinted then
    let where_ := match lane with | some l => s!"lane {l}, " | none => ""
    IO.println s!"MISMATCH batch {e.index} ({e.kind}), {where_}{field}: Rust {rust}, Lean {lean}"
  pure { t with mismatches := t.mismatches + 1 }

def compareMask (t : Tally) (e : Expected) (name : String) (rust lean : UInt8) : IO Tally := do
  let t := { t with masks := t.masks + 1 }
  if rust = lean then pure t
  else
    let diff := (List.range 8).filter fun l => (rust ^^^ lean).toNat.testBit l
    report t e none s!"{name} (lanes {diff})" (showMask rust) (showMask lean)

def compareBatch (t : Tally) (e : Expected) : IO Tally := do
  let got := decompress (modelInputs e.inputs)
  let mut t := { t with batches := t.batches + 1, lanes := t.lanes + 8 }
  t ← compareMask t e "on_curve" e.onCurve got.on_curve
  t ← compareMask t e "valid" e.valid got.valid
  t ← compareMask t e "undecided" e.undecided got.undecided
  for l in List.range 8 do
    let want := e.points[l]!
    let have_ := pointWords got.points[l]!
    for w in List.range 24 do
      t := { t with limbs := t.limbs + 1 }
      if want[w]! ≠ have_[w]! then
        t ← report t e (some l) s!"points[{l}].{fpName w}" (showHex want[w]!.toNat)
          (showHex have_[w]!.toNat)
  pure t

def run (path : String) : IO UInt32 := do
  let read ← (IO.FS.readFile path).toBaseIO
  let .ok text := read | do
    IO.eprintln s!"{path}: cannot read"
    pure 2
  match parse text with
  | .error msg =>
    IO.eprintln s!"{path}: {msg}"
    pure 2
  | .ok (h, expected) =>
    IO.println s!"vectors: seed {h.seed}, {h.count} batches"
    let start ← IO.monoMsNow
    let mut t : Tally := {}
    for e in expected do
      t ← compareBatch t e
    let elapsed := (← IO.monoMsNow) - start
    IO.println s!"compared {t.batches} batches, {t.lanes} lanes, {t.masks} masks, \
      {t.limbs} point limbs in {elapsed} ms"
    if t.mismatches = 0 then
      IO.println "all values match"
      pure 0
    else
      IO.println s!"{t.mismatches} mismatches"
      pure 1

end DifferentialTest

def main (args : List String) : IO UInt32 :=
  match args with
  | [path] => DifferentialTest.run path
  | _ => do
    IO.eprintln "usage: differential <vectors file>"
    pure 2
