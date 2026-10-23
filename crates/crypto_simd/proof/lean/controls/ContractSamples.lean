import LeanBlsSimd.Kzg.ScalarContracts
import LeanBlsSimd.Kzg.ShaContracts
import LeanBlsSimd.Kzg.PortableFp

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd LeanBlsSimd.Kzg

namespace LeanBlsSimd.Controls.ContractSamples

-- These interpreter checks sample generated functions; they prove no contract.
def check (label : String) (passed : Bool) : IO Unit := do
  unless passed do throw (IO.userError label)

def slice {α : Type} (xs : List α) : Slice α :=
  if h : xs.length ≤ Usize.max then ⟨xs, h⟩ else ⟨[], by simp⟩

def u8 (n : Nat) : U8 := ⟨BitVec.ofNat 8 n⟩

def digestBytes (n : Nat) : Aeneas.Std.Array U8 32#usize :=
  ⟨(List.range 32).map (fun i => u8 (n / 256^(31-i) % 256)), by simp⟩

def arrayEq {n : Usize} (a b : Aeneas.Std.Array U64 n) : Bool :=
  a.val.map (·.val) == b.val.map (·.val)

def resultArrayEq {n : Usize} (r : Result (Aeneas.Std.Array U64 n))
    (want : Aeneas.Std.Array U64 n) : Bool :=
  match r with | .ok out => arrayEq out want | _ => false

def frResultEq (r : Result blst.blst_fr) (want : Fr) : Bool :=
  match r with | .ok out => arrayEq out.l (frEncode want).l | _ => false

def frCase (x y : Nat) : IO Unit := do
  let a := Fr.ofNat x
  let b := Fr.ofNat y
  check "fr_add" (frResultEq (kzg.fr.fr_add (frEncode a) (frEncode b)) (a+b))
  check "fr_sub" (frResultEq (kzg.fr.fr_sub (frEncode a) (frEncode b)) (a-b))
  check "fr_mul" (frResultEq (kzg.fr.fr_mul (frEncode a) (frEncode b)) (a*b))
  check "fr_to_words" (resultArrayEq (kzg.fr.fr_to_words (frEncode a)) (words 4#usize a.val))
  check "fr_to_bytes" (match kzg.fr.fr_to_bytes (frEncode a) with
    | .ok out => arrayBytes out == Kzg.blsFieldToBytes a | _ => false)
  check "wrong scalar expectation accepted"
    (!(frResultEq (kzg.fr.fr_add (frEncode a) (frEncode b)) (a+b+1)))

def frBytesCase (n : Nat) : IO Unit := do
  let input := digestBytes n
  check "canonical scalar decoding" (match kzg.fr.fr_from_bytes input,
      Kzg.bytesToBlsField (arrayBytes input) with
    | .ok none, .error _ => true
    | .ok (some out), .ok want => arrayEq out.l (frEncode want).l
    | _, _ => false)
  check "reducing scalar decoding"
    (frResultEq (kzg.fr.fr_from_bytes_reduced input) (Fr.ofNat n))

def fpCase (bmi2 : Bool) (x y : Nat) : IO Unit :=
  letI : RuntimeFeatures := ⟨false, false, bmi2⟩
  do
    let a := Fp.ofNat x
    let b := Fp.ofNat y
    let encode (v : Fp) : portable.fp.Fp := (fpEncode v).l
    check "Fp.add" (resultArrayEq (portable.fp.Fp.add (encode a) (encode b)) (encode (a+b)))
    check "Fp.sub" (resultArrayEq (portable.fp.Fp.sub (encode a) (encode b)) (encode (a-b)))
    check "Fp.mul" (resultArrayEq (portable.fp.Fp.mul (encode a) (encode b)) (encode (a*b)))
    check "Fp.is_zero" (match portable.fp.Fp.is_zero (encode a) with
      | .ok got => got == a.isZero | _ => false)
    check "wrong Fp expectation accepted"
      (!(resultArrayEq (portable.fp.Fp.mul (encode a) (encode b)) (encode (a*b+1))))

def chunked (sizes : List Nat) : List (List U8) := Id.run do
  let message := (List.range (sizes.foldl (·+·) 0)).map (fun i => u8 (i*7+3))
  let mut out := []
  let mut start := 0
  for size in sizes do
    out := out ++ [(message.drop start).take size]
    start := start + size
  return out

def runChunks {S : Type} (new : Result S) (update : S → Slice U8 → Result S)
    (finish : S → Result (Aeneas.Std.Array U8 32#usize))
    (chunks : List (List U8)) : Result ByteArray := do
  let s ← new
  let digest ← shaContinue update finish s (chunks.map slice)
  ok (arrayBytes digest)

def shaCase (sizes : List Nat) : IO Unit := do
  let chunks := chunked sizes
  check "chunk fixture lengths" (chunks.map List.length == sizes)
  let want := Bls.sha256 (bytes chunks.flatten)
  let wrong := Bls.sha256 (bytes (chunks.flatten ++ [1#u8]))
  for result in [runChunks sha256.portable.Sha256.new sha256.portable.Sha256.update
      sha256.portable.Sha256.finish chunks,
      runChunks sha256.extensions.Sha256.new sha256.extensions.Sha256.update
      sha256.extensions.Sha256.finish chunks] do
    match result with
    | .ok out =>
      check "SHA chunk digest" (out == want)
      check "wrong SHA transcript accepted" (out != wrong)
    | _ => throw (IO.userError "generated SHA failed")

#eval (show IO Unit from do
  for (x,y) in [(0,0), (1,2), (5,3), (Fr.modulus-1,Fr.modulus-1),
      (2^254+12345,Fr.modulus-7)] do frCase x y
  for n in [0,1,Fr.modulus-1,Fr.modulus,Fr.modulus+1,2^256-1] do frBytesCase n
  check "r itself accepted" (match kzg.fr.fr_from_bytes (digestBytes Fr.modulus) with
    | .ok none => true | _ => false)
  for bmi2 in [false,true] do
    for (x,y) in [(0,0),(1,2),(Fp.modulus-1,Fp.modulus-1),(2^380+99,Fp.modulus-5)] do
      fpCase bmi2 x y
  for sizes in [[],[3],[55],[56],[63],[64],[65],[1,63,64,1],[100,0,27,200,1]] do
    shaCase sizes
  IO.println "generated Fr, FrBytes, Fp and both SHA paths: samples and negative controls passed")

end LeanBlsSimd.Controls.ContractSamples
