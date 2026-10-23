import Differential.Common
import LeanBlsSimd.Refines.DecompressG2
import LeanBlsSimd.Model.UncompressG2
import LeanBlsSimd.Spec.G2Encoding

/-!
The G2 recording uses seed/batches headers. Each batch has eight 96-byte `in`
lines, `on_curve`, `valid` and `undecided` masks, eight `pt <lane> <24 hex words>` lines, eight
`blst <lane> none|<24 hex words>` lines, and `end`. All points use x.fp[0], x.fp[1], y.fp[0], y.fp[1], six limbs each.

After batches, `wrappers <count>` declares cases. A `wrapper <index> <kind> <length>` has
`ref <batch> <lane>` for each input and `out <index> none|<24 hex words>` for each output,
then `end`. `endfile` terminates the recording. References reuse the independently recorded
blst verdicts. Both SIMD settings of the generated wrapper use those verdicts as externals.
The spec verdict is checked against blst on every recorded input, including undecided lanes.
-/

open LeanBlsSimd LeanBlsSimd.DecompressG2 Aeneas

namespace DifferentialTest

abbrev Encoding := UncompressG2.Encoding

abbrev Words := Array UInt64
abbrev Verdict := Option Words

structure Batch where
  index : Nat
  kind : String
  inputs : Array (Array UInt8)
  onCurve : UInt8
  valid : UInt8
  undecided : UInt8
  points : Array Words
  blst : Array Verdict
deriving Inhabited

structure Wrapper where
  index : Nat
  kind : String
  refs : Array (Nat × Nat)
  outputs : Array Verdict
deriving Inhabited

def pointWords (words : List String) (line : Nat) : Parser Words := do
  if words.length ≠ 24 then throw s!"line {line}: expected 24 point words"
  words.toArray.mapM fun w => match hexNat? w with
    | some v => if v < 2 ^ 64 then pure (UInt64.ofNat v) else throw s!"line {line}: word out of range"
    | none => throw s!"line {line}: bad hex word `{w}`"

def verdictLine (key : String) (lane : Nat) (allowNone : Bool := true) : Parser Verdict := do
  let (n, l) ← next
  match words l with
  | k :: index :: rest =>
    if k ≠ key || index ≠ toString lane then throw s!"line {n}: expected `{key} {lane}`"
    if rest = ["none"] && allowNone then pure none else pure (some (← pointWords rest n))
  | _ => throw s!"line {n}: expected `{key} {lane}`"

def batch (index : Nat) : Parser Batch := do
  let (n, l) ← next
  let kind ← match words l with
    | ["batch", i, kind] =>
      if i = toString index then pure kind else throw s!"line {n}: expected batch {index}"
    | _ => throw s!"line {n}: expected `batch <index> <kind>`"
  let inputs ← (Array.range 8).mapM fun _ => do
    let (n, digits) ← field "in" 192
    match hexBytes? digits with
    | some bytes => pure bytes
    | none => throw s!"line {n}: bad input hex"
  let onCurve ← maskField "on_curve"
  let valid ← maskField "valid"
  let undecided ← maskField "undecided"
  let points ← (Array.range 8).mapM fun lane => do
    let some p ← verdictLine "pt" lane false | throw "kernel point missing"
    pure p
  let blst ← (Array.range 8).mapM fun lane => verdictLine "blst" lane
  let (n, l) ← next
  if l ≠ "end" then throw s!"line {n}: expected `end`"
  pure { index, kind, inputs, onCurve, valid, undecided, points, blst }

def wrapper (index count : Nat) : Parser Wrapper := do
  let (n, l) ← next
  let (kind, len) ← match words l with
    | ["wrapper", i, kind, len] =>
      if i ≠ toString index then throw s!"line {n}: expected wrapper {index}"
      match len.toNat? with
      | some len => pure (kind, len)
      | none => throw s!"line {n}: bad wrapper length"
    | _ => throw s!"line {n}: expected `wrapper <index> <kind> <length>`"
  let refs ← (Array.range len).mapM fun _ => do
    let (n, l) ← next
    match words l with
    | ["ref", b, lane] =>
      match b.toNat?, lane.toNat? with
      | some b, some lane =>
        if b < count && lane < 8 then pure (b, lane) else throw s!"line {n}: reference out of range"
      | _, _ => throw s!"line {n}: bad reference"
    | _ => throw s!"line {n}: expected `ref <batch> <lane>`"
  let outputs ← (Array.range len).mapM fun lane => verdictLine "out" lane
  let (n, l) ← next
  if l ≠ "end" then throw s!"line {n}: expected `end`"
  pure { index, kind, refs, outputs }

def parse (text : String) : Except String (Header × Array Batch × Array Wrapper) :=
  let file : Parser (Header × Array Batch × Array Wrapper) := do
    let h ← header
    if h.count = 0 then throw "no G2 batches"
    let batches ← (Array.range h.count).mapM batch
    let countText ← headerLine "wrappers"
    let some count := countText.toNat? | throw "bad wrapper count"
    if count = 0 then throw "no wrapper cases"
    let wrappers ← (Array.range count).mapM fun i => wrapper i h.count
    let (n, l) ← next
    if l ≠ "endfile" then throw s!"line {n}: expected `endfile`"
    if !(← get).isEmpty then throw "text after endfile"
    pure (h, batches, wrappers)
  (file.run (meaningful text)).map (·.1)

def encoding (bytes : Array UInt8) : Encoding := .ofFn fun i => bytes[i.val]!

def modelInputs (inputs : Array (Array UInt8)) : Vector Encoding 8 :=
  .ofFn fun lane => encoding inputs[lane.val]!

def modelPoint (words : Words) : BlstP2Affine :=
  point (.ofFn fun i => words[i.val]!) (.ofFn fun i => words[6 + i.val]!)
    (.ofFn fun i => words[12 + i.val]!) (.ofFn fun i => words[18 + i.val]!)

def wordsOfPoint (p : BlstP2Affine) : Words :=
  (p.x.fp[0].l.toList ++ p.x.fp[1].l.toList ++ p.y.fp[0].l.toList ++ p.y.fp[1].l.toList).toArray

def wordsOfExtracted (p : silver_crypto_simd.blst.blst_p2_affine) : Words :=
  ((p.x.fp.val ++ p.y.fp.val).flatMap fun fp => fp.l.val).toArray.map fun x => UInt64.ofBitVec x.bv

structure Tally where
  comparisons : Nat := 0
  mismatches : Nat := 0

def check {α : Type} [BEq α] [Repr α] (t : Tally) (context : String) (want got : α) : IO Tally := do
  let t := { t with comparisons := t.comparisons + 1 }
  if want == got then pure t else
    if t.mismatches < 40 then IO.println s!"MISMATCH {context}: Rust {repr want}, Lean {repr got}"
    pure { t with mismatches := t.mismatches + 1 }

def failed (t : Tally) (context msg : String) : IO Tally := do
  if t.mismatches < 40 then IO.println s!"MISMATCH {context}: expected ok, got {msg}"
  pure { t with comparisons := t.comparisons + 1, mismatches := t.mismatches + 1 }

def compareKernel (t : Tally) (label : String) (b : Batch)
    (onCurve valid undecided : UInt8) (points : Array Words) : IO Tally := do
  let context := s!"G2 {label} batch {b.index} ({b.kind})"
  let mut t ← check t s!"{context} on_curve" b.onCurve onCurve
  t ← check t s!"{context} valid" b.valid valid
  t ← check t s!"{context} undecided" b.undecided undecided
  for lane in List.range 8 do
    for word in List.range 24 do
      t ← check t s!"{context} lane {lane} limb {word}" (b.points[lane]!)[word]! (points[lane]!)[word]!
  pure t

def compareBatch (t : Tally) (b : Batch) : IO Tally := do
  let inputs := modelInputs b.inputs
  let model := DecompressG2.decompress inputs
  let mut t ← compareKernel t "model" b model.on_curve model.valid model.undecided
    (model.points.toArray.map wordsOfPoint)
  match silver_crypto_simd.bls.decompress_g2.decompress (toArray (toArray toU8) inputs) with
  | .ok got =>
    t ← compareKernel t "extraction" b (UInt8.ofBitVec got.on_curve.bv) (UInt8.ofBitVec got.valid.bv)
      (UInt8.ofBitVec got.undecided.bv) (got.points.val.toArray.map wordsOfExtracted)
  | .fail e => t ← failed t s!"G2 extraction batch {b.index}" s!"fail {repr e}"
  | .div => t ← failed t s!"G2 extraction batch {b.index}" "div"
  pure t

def compareSpec (t : Tally) (b : Batch) : IO Tally := do
  let mut t := t
  for lane in List.range 8 do
    let spec := (G2Spec.verdict (encoding b.inputs[lane]!)).map wordsOfPoint
    t ← check t s!"G2 spec/blst batch {b.index} ({b.kind}) lane {lane}" b.blst[lane]! spec
  pure t

def compareWrapper (t : Tally) (batches : Array Batch) (w : Wrapper) (simd : Bool) : IO Tally := do
  let entries := w.refs.toList.map fun (b, l) =>
    (encoding batches[b]!.inputs[l]!, batches[b]!.blst[l]!.map modelPoint)
  let oracle := fun input : Encoding =>
    match entries.find? (fun entry => entry.1 == input) with
    | some entry => entry.2
    | none => none
  let inputs := entries.map Prod.fst
  let context := s!"G2 wrapper {w.index} ({w.kind}, length {inputs.length}, simd={simd})"
  let want := w.outputs
  let model := (UncompressG2.uncompress simd oracle inputs).toArray.map (Option.map wordsOfPoint)
  let t ← check t s!"{context} model" want model
  letI : silver_crypto_simd.RuntimeFeatures := {
    simdAvailable := simd
    shaAvailable := false
    bmi2Available := false }
  letI : silver_crypto_simd.bls.BlsExternals := {
    uncompressG2 := fun bytes => (oracle (ofArray ofU8 bytes)).map toBlstP2Affine }
  let extracted : List (Std.Array Std.U8 96#usize) := inputs.map (toArray toU8)
  if h : extracted.length ≤ Std.Usize.max then do
    let inputSlice : Aeneas.Std.Slice (Std.Array Std.U8 96#usize) := ⟨extracted, h⟩
    let sentinel := toBlstP2Affine (modelPoint ((Array.replicate 6 0xfeed) ++ Array.replicate 6 0xbeef ++
      Array.replicate 6 0xcafe ++ Array.replicate 6 0xdead))
    let out : Aeneas.Std.Slice (Option silver_crypto_simd.blst.blst_p2_affine) :=
      ⟨List.replicate extracted.length (some sentinel), by simpa using h⟩
    match silver_crypto_simd.bls.uncompress_in_g2 inputSlice out with
    | .ok got => check t s!"{context} extraction" want (got.val.toArray.map (Option.map wordsOfExtracted))
    | .fail e => failed t s!"{context} extraction" s!"fail {repr e}"
    | .div => failed t s!"{context} extraction" "div"
  else do
    failed t context "input length exceeds usize"

def run (path : String) : IO UInt32 := do
  let .ok text ← (IO.FS.readFile path).toBaseIO | do
    IO.eprintln s!"{path}: cannot read"; pure 2
  match parse text with
  | .error msg => IO.eprintln s!"{path}: {msg}"; pure 2
  | .ok (h, batches, wrappers) =>
    IO.println s!"G2 vectors: seed {h.seed}, {h.count} batches, {wrappers.size} wrappers"
    let start ← IO.monoMsNow
    let mut t : Tally := {}
    for b in batches do t ← compareBatch t b
    let kernelsDone ← IO.monoMsNow
    for b in batches do t ← compareSpec t b
    let specDone ← IO.monoMsNow
    for w in wrappers do
      for simd in [false, true] do t ← compareWrapper t batches w simd
    IO.println s!"G2: {batches.size * 8} lanes, {batches.size * 6} kernel masks, \
      {batches.size * 8 * 24 * 2} kernel limbs, {batches.size * 8} spec/blst verdicts, \
      {wrappers.size * 2} wrapper cases per implementation; {t.comparisons} comparisons \
      in {(← IO.monoMsNow) - start} ms"
    IO.println s!"G2 timing: kernels {kernelsDone - start} ms, spec/blst {specDone - kernelsDone} ms, wrappers {(← IO.monoMsNow) - specDone} ms"
    if t.mismatches = 0 then IO.println "all G2 values match"; pure 0
    else IO.println s!"{t.mismatches} G2 mismatches"; pure 1

end DifferentialTest
