import LeanBlsSimd.Extracted.Funs

namespace DifferentialTest

structure Header where
  seed : String
  count : Nat

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

/-- Nonempty, noncomment lines with their original 1-based line numbers. -/
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

def headerLine (key : String) : Parser String := do
  let (n, l) ← next
  match words l with
  | [k, v] => if k = key then pure v else throw s!"line {n}: expected `{key} <value>`"
  | _ => throw s!"line {n}: expected `{key} <value>`"

def header : Parser Header := do
  let seed ← headerLine "seed"
  let countText ← headerLine "batches"
  match countText.toNat? with
  | some count => pure { seed, count }
  | none => throw s!"bad batch count `{countText}`"

def field (key : String) (digits : Nat) : Parser (Nat × String) := do
  let (n, l) ← next
  match words l with
  | [k, v] =>
    if k = key && v.length = digits then pure (n, v)
    else throw s!"line {n}: expected `{key}` with {digits} hex digits"
  | _ => throw s!"line {n}: expected `{key}` with {digits} hex digits"

def maskField (key : String) : Parser UInt8 := do
  let (n, v) ← field key 2
  match hexNat? v with
  | some m => pure (UInt8.ofNat m)
  | none => throw s!"line {n}: bad hex in `{key}`"


end DifferentialTest
