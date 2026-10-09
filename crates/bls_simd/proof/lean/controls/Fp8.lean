import LeanBlsSimd.Proofs.Convert
import LeanBlsSimd.Proofs.Pow

/-! Negative controls for `Proofs/Vector.lean`, `Proofs/Carries.lean`, `Proofs/Fp8.lean`,
`Proofs/Pow.lean` and `Proofs/Convert.lean`. Each
`fail_if_success` wraps a claim that must fail; each plain `example` must pass.

Each mutant runs through a copy of the model that takes the mutated part as a parameter; an
`example` pins the copy to the model by `rfl`. A mutant is shown wrong on concrete inputs that
satisfy the lemma's hypotheses, by `decide +kernel`, beside the model passing the same check. -/

namespace LeanBlsSimd

open EthCryptographySpecs.Bls

-- A mutated proof stops at its first failing step, so the linter flags the steps after it.
set_option linter.unreachableTactic false

/-! ## Inputs -/

/-- p in every lane: the field's zero, not canonical. -/
def pFp8 : Fp8 := .splat_limbs (.ofList P)

/-- 1 in every lane: Montgomery form of R⁻¹. -/
def oneFp8 : Fp8 := .splat_limbs (.ofList ONE_PLAIN)

/-- 2p − 1 in every lane, the largest value `Fp8Inv` allows. -/
def maxFp8 : Fp8 := .splat_limbs (.ofList (limbs52 (2 * Fp.modulus - 1)))

example (l : Fin 8) : Fp8Inv (pFp8.lane l) ∧ Fp8Inv (oneFp8.lane l) ∧ Fp8Inv (maxFp8.lane l) := by
  simp only [pFp8, oneFp8, maxFp8, Fp8.lane_splat_limbs]
  exact ⟨⟨by decide, by decide +kernel⟩, ⟨by decide, by decide +kernel⟩,
    ⟨by decide, by decide +kernel⟩⟩

/-- Lane `l` holds limbs `8 l + j`, so every lane differs. -/
def distinct : Vector Limbs 8 := .ofFn fun l => .ofFn fun j => .ofNat (8 * l.val + j.val)

/-! ## `_mm512_set_epi64` puts its last argument in lane 0

`Fp8.load` passes `values[7][j]` first. With the arguments taken in the other order, lane 0
would receive `values[7]`, and `Fp8.lane_load` would fail. -/

def set_epi64Rev (e7 e6 e5 e4 e3 e2 e1 e0 : Int64) : M512 :=
  #v[e7, e6, e5, e4, e3, e2, e1, e0].map Int64.toUInt64

def loadWith (set : Int64 → Int64 → Int64 → Int64 → Int64 → Int64 → Int64 → Int64 → M512)
    (values : Vector Limbs 8) : Fp8 :=
  ⟨.ofFn fun j => set values[7][j].toInt64 values[6][j].toInt64 values[5][j].toInt64
    values[4][j].toInt64 values[3][j].toInt64 values[2][j].toInt64 values[1][j].toInt64
    values[0][j].toInt64⟩

example : loadWith _mm512_set_epi64 = Fp8.load := rfl

example : (loadWith _mm512_set_epi64 distinct).lane 0 = distinct[0] := by decide +kernel

example : ((loadWith set_epi64Rev distinct).lane 0)[0].toNat ≠ distinct[0][0].toNat := by
  decide +kernel

/-! ## Bit `l` of `_mm512_cmpeq_epi64_mask` is lane `l`

A mask with its bits reversed reports lane 0 in bit 7. -/

def cmpeqRev (a b : M512) : Mmask8 :=
  .ofNat ((List.finRange 8).map fun l => if a[l] = b[l] then 2 ^ (7 - l.val) else 0).sum

/-- Equal in lane 0 only. -/
def lane0 : M512 × M512 := (#v[5, 1, 1, 1, 1, 1, 1, 1], #v[5, 2, 2, 2, 2, 2, 2, 2])

example : (_mm512_cmpeq_epi64_mask lane0.1 lane0.2).toNat.testBit 0 = true := by decide

example : (cmpeqRev lane0.1 lane0.2).toNat.testBit 0 = false := by decide

example : True := by
  fail_if_success
    have : ∀ (a b : M512) (l : Fin 8), (cmpeqRev a b).toNat.testBit l = decide (a[l] = b[l]) :=
      fun a b l => by
        have h := testBit_mask8 (decide (a[0] = b[0])) (decide (a[1] = b[1]))
          (decide (a[2] = b[2])) (decide (a[3] = b[3])) (decide (a[4] = b[4]))
          (decide (a[5] = b[5])) (decide (a[6] = b[6])) (decide (a[7] = b[7])) l
        have hv : #v[decide (a[0] = b[0]), decide (a[1] = b[1]), decide (a[2] = b[2]),
            decide (a[3] = b[3]), decide (a[4] = b[4]), decide (a[5] = b[5]),
            decide (a[6] = b[6]), decide (a[7] = b[7])] =
            .ofFn fun i : Fin 8 => decide (a[i] = b[i]) := by
          ext i hi
          interval_cases i <;> rfl
        rw [hv] at h
        simpa [cmpeqRev] using h
  trivial

/-! ## `canonical`: the blend keeps `self` where the subtraction borrowed

With the blend's operands swapped, p stays p: not below p, and not p mod p. -/

def canonicalWith (blend : Mmask8 → Vector M512 LIMBS → Vector M512 LIMBS → Vector M512 LIMBS)
    (self : Fp8) : Fp8 :=
  let (d, borrow) := Simd.sub_limbs self.limbs (Simd.splat_limbs (.ofList P))
  ⟨blend (Simd.borrowed borrow) d self.limbs⟩

def blendRev (k : Mmask8) (a b : Vector M512 LIMBS) : Vector M512 LIMBS := Simd.blend k b a

example : canonicalWith Simd.blend = Fp8.canonical := rfl

example : val ((canonicalWith Simd.blend pFp8).lane 0) = val (pFp8.lane 0) % Fp.modulus := by
  decide +kernel

example : val ((canonicalWith blendRev pFp8).lane 0) ≠ val (pFp8.lane 0) % Fp.modulus := by
  decide +kernel

/-! ## `sub_limbs`: the borrow is spread by an arithmetic shift

With a logical shift, `srli 63`, a borrow is 1 rather than all ones. The next limb then adds 1
where it should subtract 1, and `borrowed` never matches all ones. 0 − 1 shows it: the first limb
emits 1 instead of all ones, the following limb clears it, and the final borrow is 0, not the
all-ones that `sub_limbs_spec` states. -/

def sub_limbsWith (shift : M512 → M512) (a b : Vector M512 LIMBS) : Vector M512 LIMBS × M512 :=
  let mask := Simd.splat (.ofNat MASK52)
  (List.finRange LIMBS).foldl (init := (.replicate _ Simd.zero, Simd.zero))
    fun (d, borrow) (j : Fin LIMBS) =>
      let s := _mm512_add_epi64 (_mm512_sub_epi64 a[j] b[j]) borrow
      let borrow := shift s
      (d.set j (_mm512_and_si512 s mask), borrow)

example : sub_limbsWith (_mm512_srai_epi64 63) = Simd.sub_limbs := rfl

example : (sub_limbsWith (_mm512_srai_epi64 63) Fp8.zero.limbs oneFp8.limbs).2[0] =
    Lane.borrowOf (decide (val (Fp8.zero.lane 0) < val (oneFp8.lane 0))) := by
  decide +kernel

example : (sub_limbsWith (_mm512_srli_epi64 63) Fp8.zero.limbs oneFp8.limbs).2[0] ≠
    Lane.borrowOf (decide (val (Fp8.zero.lane 0) < val (oneFp8.lane 0))) := by
  decide +kernel

/-! ## `eq_mask`: canonical lanes, and every bit set at the start

p and 0 are the same field element in every lane, so every bit of their `eq_mask` is set. Two
mutants clear one: an initial mask of `0x7f`, which drops lane 7, and a comparison of the raw
limbs, without `canonical`. -/

def eq_maskWith (canon : Fp8 → Fp8) (init : Mmask8) (self rhs : Fp8) : Mmask8 :=
  let a := canon self
  let b := canon rhs
  (List.finRange LIMBS).foldl (init := init) fun k (j : Fin LIMBS) =>
    k &&& _mm512_cmpeq_epi64_mask a.limbs[j] b.limbs[j]

example : eq_maskWith Fp8.canonical 0xff = Fp8.eq_mask := rfl

example (l : Fin 8) : val (pFp8.lane l) % Fp.modulus = val (Fp8.zero.lane l) % Fp.modulus := by
  rw [pFp8, Fp8.lane_splat_limbs, Fp8.lane_zero]
  decide +kernel

example : eq_maskWith Fp8.canonical 0xff pFp8 Fp8.zero = 0xff := by decide +kernel

example : (eq_maskWith Fp8.canonical 0x7f pFp8 Fp8.zero).toNat.testBit 7 = false := by
  decide +kernel

example : (eq_maskWith id 0xff pFp8 Fp8.zero).toNat.testBit 0 = false := by decide +kernel

/-! ## `is_zero_mask`: canonical lanes

p holds zero, but its raw limbs are not zero. -/

def is_zero_maskWith (canon : Fp8 → Fp8) (self : Fp8) : Mmask8 :=
  let a := canon self
  (List.finRange LIMBS).foldl (init := 0xff) fun k (j : Fin LIMBS) =>
    k &&& _mm512_cmpeq_epi64_mask a.limbs[j] Simd.zero

example : is_zero_maskWith Fp8.canonical = Fp8.is_zero_mask := rfl

example : is_zero_maskWith Fp8.canonical pFp8 = 0xff := by decide +kernel

example : (is_zero_maskWith id pFp8).toNat.testBit 0 = false := by decide +kernel

/-! ## `select`: lanes of `k` take `b`

With the blend reversed, lane 0 of mask 1 takes `a`. -/

def selectWith (blend : Mmask8 → Vector M512 LIMBS → Vector M512 LIMBS → Vector M512 LIMBS)
    (k : Mmask8) (a b : Fp8) : Fp8 :=
  ⟨blend k a.limbs b.limbs⟩

example : selectWith Simd.blend = Fp8.select := rfl

example : (selectWith Simd.blend 1 Fp8.zero oneFp8).lane 0 = oneFp8.lane 0 := by decide +kernel

example : ((selectWith blendRev 1 Fp8.zero oneFp8).lane 0)[0].toNat ≠ (oneFp8.lane 0)[0].toNat := by
  decide +kernel

/-! ## `add`: subtract 2p where the sum is not below 2p

`Fp8Inv.bound` fails for both mutants. With the blend reversed, 0 + 0 takes the wrapped
difference 0 − 2p. Subtracting p rather than 2p leaves (2p − 1) + (2p − 1) at 3p − 2, which is
still the right residue. -/

def addWith (blend : Mmask8 → Vector M512 LIMBS → Vector M512 LIMBS → Vector M512 LIMBS)
    (modulus : Vector M512 LIMBS) (self rhs : Fp8) : Fp8 :=
  let s := Simd.add_limbs self.limbs rhs.limbs
  let (d, borrow) := Simd.sub_limbs s modulus
  ⟨blend (Simd.borrowed borrow) d s⟩

example : addWith Simd.blend Simd.two_p = Fp8.add := rfl

example : val ((addWith Simd.blend Simd.two_p Fp8.zero Fp8.zero).lane 0) < 2 * Fp.modulus ∧
    val ((addWith Simd.blend Simd.two_p maxFp8 maxFp8).lane 0) < 2 * Fp.modulus := by
  decide +kernel

example : ¬ val ((addWith blendRev Simd.two_p Fp8.zero Fp8.zero).lane 0) < 2 * Fp.modulus := by
  decide +kernel

example : ¬ val ((addWith Simd.blend (Simd.splat_limbs (.ofList P)) maxFp8 maxFp8).lane 0) <
      2 * Fp.modulus ∧
    val ((addWith Simd.blend (Simd.splat_limbs (.ofList P)) maxFp8 maxFp8).lane 0) %
      Fp.modulus = (val (maxFp8.lane 0) + val (maxFp8.lane 0)) % Fp.modulus := by
  decide +kernel

/-! ## `sub`: add 2p back where the subtraction borrowed

With the logical borrow shift of `sub_limbsWith`, 0 − 1 gives 2^53 − 1: the borrow out of limb 0
adds 1 to limb 1 instead of subtracting it, and `borrowed` never fires. The result is below 2p
but is not −1 modulo p. -/

def subWith (sub : Vector M512 LIMBS → Vector M512 LIMBS → Vector M512 LIMBS × M512)
    (self rhs : Fp8) : Fp8 :=
  let (d, borrow) := sub self.limbs rhs.limbs
  let wrapped := Simd.add_limbs d Simd.two_p
  ⟨Simd.blend (Simd.borrowed borrow) d wrapped⟩

example : subWith Simd.sub_limbs = Fp8.sub := rfl

example : val ((subWith Simd.sub_limbs Fp8.zero oneFp8).lane 0) = 2 * Fp.modulus - 1 := by
  decide +kernel

example : val ((subWith (sub_limbsWith (_mm512_srli_epi64 63)) Fp8.zero oneFp8).lane 0) =
    2 ^ 53 - 1 := by
  decide +kernel

/-! ## `neg` is `0 − self`

With the operands swapped, the negation of 1 is 1, which is not −1 modulo p. -/

example : (val (oneFp8.neg.lane 0) + val (oneFp8.lane 0)) % Fp.modulus = 0 := by decide +kernel

example : (val ((oneFp8.sub Fp8.zero).lane 0) + val (oneFp8.lane 0)) % Fp.modulus ≠ 0 := by
  decide +kernel

/-! ## `half` multiplies by `HALF_MONT`

`decode_lane_half` says 2 · `half x` ≡ x. `HALF_P_MINUS_1`, the plain (p − 1)/2 that
`is_larger_root_mask` uses, is the table a slip would pick; with it the doubling fails. -/

def halfWith (table : List ℕ) (self : Fp8) : Fp8 := self.mul (.splat_limbs (.ofList table))

example : halfWith HALF_MONT = Fp8.half := rfl

example : 2 * val ((halfWith HALF_MONT oneFp8).lane 0) % Fp.modulus =
    val (oneFp8.lane 0) % Fp.modulus := by
  decide +kernel

example : 2 * val ((halfWith HALF_P_MINUS_1 oneFp8).lane 0) % Fp.modulus ≠
    val (oneFp8.lane 0) % Fp.modulus := by
  decide +kernel

/-! ## `store` puts limb `j` of lane `l` at `out[l][j]`

`LIMBS` and `LANES` are both 8, so the transposed write `out[j][l]` type-checks; it returns limbs
where lanes belong. -/

def storeT (self : Fp8) : Vector Limbs 8 :=
  (List.finRange LIMBS).foldl (init := .replicate 8 (.replicate LIMBS 0)) fun out (j : Fin LIMBS) =>
    let l := Simd.lanes self.limbs[j]
    (List.finRange 8).foldl (init := out) fun out (lane : Fin 8) =>
      out.set j (out[j].set lane l[lane])

example : (Fp8.load distinct).store[1][0].toNat = distinct[1][0].toNat := by decide +kernel

example : (storeT (Fp8.load distinct))[1][0].toNat ≠ distinct[1][0].toNat := by decide +kernel

/-! ## `pow_p_minus_3_over_4`: windows from the top, four squarings each

The proof turns the window loop into Horner's rule over the windows from window 94 down, with
base 16 (`window_step`, `windows_horner`). Taken from window 0 up, or with base 8, the exponent is
not (p − 3)/4. With three squarings per window, the step of `window_step`'s proof that reaches
16e fails: three squarings reach 8e. -/

example : (List.range 94).foldl (fun e w => 16 * e + P_MINUS_3_OVER_4_WINDOWS[w]!)
    P_MINUS_3_OVER_4_WINDOWS[94]! ≠ (Fp.modulus - 3) / 4 := by
  decide +kernel

example : (List.range 94).reverse.foldl (fun e w => 8 * e + P_MINUS_3_OVER_4_WINDOWS[w]!)
    P_MINUS_3_OVER_4_WINDOWS[94]! ≠ (Fp.modulus - 3) / 4 := by
  decide +kernel

example : True := by
  fail_if_success
    have : ∀ {x r : Fp8} {l : Fin 8} {e : ℕ}, Fp8Inv (r.lane l) →
        decode (r.lane l) = decode (x.lane l) ^ e →
        decode (r.square.square.square.lane l) = decode (x.lane l) ^ (16 * e) := by
      intro x r l e hr hd
      rw [Fp8.decode_lane_square (Fp8.inv_square (Fp8.inv_square hr)),
        Fp8.decode_lane_square (Fp8.inv_square hr), Fp8.decode_lane_square hr, hd, ← pow_mul,
        ← pow_mul, ← pow_mul]
      ring_nf
  trivial

/-! ## `sqrt_candidate` multiplies the power by `self`

Without that product the exponent stays (p − 3)/4, and `lane_sqrt_candidate`'s last step fails. -/

example : True := by
  fail_if_success
    have : ∀ {x : Fp8} {l : Fin 8}, Fp8Inv (x.lane l) →
        decode (x.pow_p_minus_3_over_4.lane l) = decode (x.lane l) ^ ((Fp.modulus + 1) / 4) := by
      intro x l hx
      rw [(Fp8.lane_pow_p_minus_3_over_4 hx).2]
  trivial

/-! ## `from_plain` multiplies by R² mod p, and `to_plain` by 1

Multiplying by R mod p instead leaves a plain value v as v, not as its Montgomery form vR.
`to_plain` without `canonical` maps p, the field's zero, to p itself: the Montgomery product of p
and 1 is (p + (R − 1)p)/R = p. -/

def from_plainWith (table : List ℕ) (values : Vector Limbs 8) : Fp8 :=
  (Fp8.load values).mul (.splat_limbs (.ofList table))

example : from_plainWith R2_MOD_P = Fp8.from_plain := rfl

example : val ((from_plainWith R2_MOD_P distinct).lane 1) % Fp.modulus =
    toMont (val distinct[1]) := by
  decide +kernel

example : val ((from_plainWith R_MOD_P distinct).lane 1) % Fp.modulus ≠
    toMont (val distinct[1]) := by
  decide +kernel

def to_plainWith (canon : Fp8 → Fp8) (self : Fp8) : Vector Limbs 8 :=
  (canon (self.mul (.splat_limbs (.ofList ONE_PLAIN)))).store

example : to_plainWith Fp8.canonical = Fp8.to_plain := rfl

example : val (to_plainWith Fp8.canonical pFp8)[0] = 0 := by decide +kernel

example : val (to_plainWith id pFp8)[0] = Fp.modulus := by decide +kernel

/-! ## `is_larger_root_mask` compares the plain value: (p − 1)/2 minus it borrows

1 is the smaller root of 1, so bit 0 is clear. Two mutants set it: subtracting in the other order,
and comparing the Montgomery form, R mod p, which exceeds (p − 1)/2. -/

def is_larger_root_maskWith (plainOf : Fp8 → Vector Limbs 8) (swap : Bool) (self : Fp8) :
    Mmask8 :=
  let plain := Fp8.load (plainOf self)
  let half := Simd.splat_limbs (.ofList HALF_P_MINUS_1)
  let (_, borrow) := if swap then Simd.sub_limbs plain.limbs half else Simd.sub_limbs half plain.limbs
  Simd.borrowed borrow

example : is_larger_root_maskWith Fp8.to_plain false = Fp8.is_larger_root_mask := rfl

example : (is_larger_root_maskWith Fp8.to_plain false Fp8.one).toNat.testBit 0 = false := by
  decide +kernel

example : (is_larger_root_maskWith Fp8.to_plain true Fp8.one).toNat.testBit 0 = true := by
  decide +kernel

example : (is_larger_root_maskWith Fp8.store false Fp8.one).toNat.testBit 0 = true := by
  decide +kernel

/-! ## `unpack52` and `pack64` on p, whose two forms `constants.rs` lists as `P_U64` and `P`

Mutants: `unpack52` taking the next word only from shift 17 up, which drops 4 bits of limb 4, and
`pack64` shifting each limb by the bit count after its own 52 bits are added. A third,
`acc_bits > 64` for `≥ 64`, is equivalent: the count after each limb is 52, 104, 92, 80, 68, 56,
108 or 96, never 64. -/

def P_U64v : Vector UInt64 6 := .ofFn fun j => .ofNat (P_U64.getD j 0)

def unpack52With (threshold : ℕ) (x : Vector UInt64 6) : Limbs :=
  .ofFn fun j =>
    let bit := j.val * LIMB_BITS
    let word := bit / 64
    let shift := bit % 64
    have hword : word < 6 := by
      show j.val * LIMB_BITS / 64 < 6
      have := j.isLt
      simp only [LIMBS, LIMB_BITS] at this ⊢
      omega
    let v := x[word] >>> shift.toUInt64
    let v :=
      if h : shift > threshold ∧ word + 1 < 6 then v ||| x[word + 1]'h.2 <<< (64 - shift).toUInt64
      else v
    v &&& .ofNat MASK52

example : unpack52With 12 = unpack52 := rfl

example : unpack52 P_U64v = .ofList P := by decide +kernel

example : val (unpack52With 16 P_U64v) ≠ val64 P_U64v := by decide +kernel

def pack64With (late : Bool) (x : Limbs) : Vector UInt64 6 :=
  let (out, acc, _, word) := (List.finRange LIMBS).foldl
    (init := (Vector.replicate 6 (0 : UInt64), (0 : BitVec 128), (0 : ℕ), (0 : ℕ)))
    fun (out, acc, acc_bits, word) (j : Fin LIMBS) =>
      let shift := if late then acc_bits + LIMB_BITS else acc_bits
      let acc := acc ||| x[j].toBitVec.setWidth 128 <<< shift
      let acc_bits := acc_bits + LIMB_BITS
      if acc_bits ≥ 64 then
        (out.set! word (.ofBitVec (acc.setWidth 64)), acc >>> 64, acc_bits - 64, word + 1)
      else (out, acc, acc_bits, word)
  if h : word < 6 then out.set word (.ofBitVec (acc.setWidth 64)) h else out

example : pack64With false = pack64 := rfl

example : pack64 (.ofList P) = P_U64v := by decide +kernel

example : val64 (pack64With true (.ofList P)) ≠ Fp.modulus := by decide +kernel

/-! ## `to_blst_limbs` is canonical

Without `canonical`, p, the field's zero, comes out as the words of p. -/

def to_blst_limbsWith (canon : Fp8 → Fp8) (self : Fp8) : Vector (Vector UInt64 6) 8 :=
  let t := (canon (self.mul (.splat_limbs (.ofList TWO_POW_384_MOD_P)))).store
  .ofFn fun lane => pack64 t[lane]

example : to_blst_limbsWith Fp8.canonical = Fp8.to_blst_limbs := rfl

example : val64 (to_blst_limbsWith Fp8.canonical pFp8)[0] = 0 := by decide +kernel

example : val64 (to_blst_limbsWith id pFp8)[0] = Fp.modulus := by decide +kernel

end LeanBlsSimd
