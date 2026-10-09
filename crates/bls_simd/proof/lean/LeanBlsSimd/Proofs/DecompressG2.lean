import LeanBlsSimd.Proofs.Decode
import LeanBlsSimd.Proofs.G2x8

/-!
# `decompress`, lane by lane, against the spec

`Kernel.laneX`, `laneY`, `laneOnCurve`, `laneUndecided` and `laneValid` restate one lane of
`decompress` over the field, from that lane's bytes alone and without the early returns.
`decompress_lane` shows that each lane of the model gives exactly those verdicts, and the point
`blstPoint (laneX b) (laneY b)` wherever `on_curve` is set. So a lane's verdicts depend only on its
own bytes (`decompress_lane_independent`), and the early returns change no verdict
(`decompress_eq_full`).

Against the spec, on a lane that is not undecided: `on_curve` is set exactly when `G2.uncompress`
succeeds, and then `points` holds the decoded point in blst's limbs (`decompress_onCurve`);
`valid` is set exactly when the decoded point P satisfies ψ(P) = [z]P (`decompress_valid`).

No proof unfolds `Fp2.sqrt`. `uncompress_eq` abstracts it before unfolding `G2.uncompress`, and
the root step goes through `Kernel.sqrt_agrees` and `Kernel.sqrt_fails`. Lean's kernel would
otherwise evaluate the large-exponent powers inside it.
-/

namespace LeanBlsSimd

open EthCryptographySpecs.Bls DecompressG2

namespace DecompressG2

theorem fromBytesBE_ok {B : ByteArray} {v : ℕ} (hs : B.size = 48) (hv : Fp.bytesBEToNat B = v)
    (hp : v < Fp.modulus) : Fp.fromBytesBE B = .ok ⟨v, hp⟩ := by
  unfold Fp.fromBytesBE
  rw [if_neg (by rw [hs]; decide)]
  subst hv
  rw [dif_pos hp]

theorem fromBytesBE_error {B : ByteArray} {v : ℕ} (hv : Fp.bytesBEToNat B = v)
    (hp : ¬v < Fp.modulus) : ∀ c, Fp.fromBytesBE B ≠ .ok c := by
  intro c h
  unfold Fp.fromBytesBE at h
  by_cases hs : B.size ≠ 48
  · rw [if_pos hs] at h
    cases h
  · rw [if_neg hs] at h
    dsimp only at h
    subst hv
    rw [dif_neg hp] at h
    cases h

/-- `G2.uncompress` on a compressed, finite encoding with both coordinates below p, up to its
square root. -/
theorem uncompress_eq {b : Vector UInt8 G2_COMPRESSED_LEN}
    (hc : ¬(b[0]'zero_lt_G2_COMPRESSED_LEN &&& 0x80 = 0))
    (hi : ¬(b[0]'zero_lt_G2_COMPRESSED_LEN &&& 0x40 ≠ 0))
    (h1 : bytesVal (clearFlags (split_at b).1).toList < Fp.modulus)
    (h0 : bytesVal (split_at b).2.toList < Fp.modulus) :
    G2.uncompress (toBytes b) =
      let x : Fp2 := ⟨⟨_, h0⟩, ⟨_, h1⟩⟩
      match Fp2.sqrt (x * x * x + G2.bTwist) with
      | .error _ => .error .invalidG2Point
      | .ok yPos =>
        .ok ⟨x, if Fp2.signBit yPos = decide (b[0]'zero_lt_G2_COMPRESSED_LEN &&& 0x20 ≠ 0) then yPos
          else -yPos, Fp2.one⟩ := by
  unfold G2.uncompress
  generalize Fp2.sqrt = sq
  rw [if_neg (by rw [size_toBytes]; decide)]
  dsimp only
  have e1 := bytesBEToNat_c1 b
  have e0 := bytesBEToNat_c0 b
  rw [get!_toBytes_zero] at e1 e0 ⊢
  have hsz (i j : ℕ) (hj : j ≤ 96) :
      (((toBytes b).set! 0 (b[0]'zero_lt_G2_COMPRESSED_LEN &&& 0x1f)).extract i j).size = j - i := by
    rw [ByteArray.size_extract, show ((toBytes b).set! 0 _).size = 96 from by
      simp [toBytes, ByteArray.set!, ByteArray.size, G2_COMPRESSED_LEN]]
    omega
  rw [if_neg (by simpa using hc), if_neg hi, fromBytesBE_ok (hsz 0 48 (by decide)) e1 h1,
    fromBytesBE_ok (hsz 48 96 le_rfl) e0 h0]
  dsimp only
  split <;> rename_i heq <;> rw [heq]
  rename_i yPos
  dsimp only
  congr 2
  by_cases hs : Fp2.signBit yPos = decide (b[0]'zero_lt_G2_COMPRESSED_LEN &&& 0x20 ≠ 0)
  · rw [if_pos hs, if_pos (by rw [hs]; simp)]
  · rw [if_neg hs, if_neg (fun h => hs (by rw [Bool.eq_iff_iff, decide_eq_true_iff, ← h]))]

/-- An encoding that `decode` marks invalid, and not undecided, fails `G2.uncompress`. -/
theorem uncompress_of_invalid {b : Vector UInt8 G2_COMPRESSED_LEN}
    (hu : (decodeLane b).undecided = false) (hv : (decodeLane b).invalid = true) :
    ∀ P, G2.uncompress (toBytes b) ≠ .ok P := by
  intro P hP
  unfold G2.uncompress at hP
  generalize Fp2.sqrt = sq at hP
  rw [if_neg (by rw [size_toBytes]; decide)] at hP
  dsimp only at hP
  have e1 := bytesBEToNat_c1 b
  have e0 := bytesBEToNat_c0 b
  rw [get!_toBytes_zero] at e1 e0 hP
  unfold decodeLane at hu hv
  dsimp only at hu hv
  by_cases hc : b[0]'zero_lt_G2_COMPRESSED_LEN &&& 0x80 = 0
  · rw [if_pos (by simpa using hc)] at hP
    cases hP
  rw [if_neg hc] at hu hv
  rw [if_neg (by simpa using hc)] at hP
  by_cases hi : b[0]'zero_lt_G2_COMPRESSED_LEN &&& 0x40 ≠ 0
  · rw [if_pos hi] at hu
    cases hu
  rw [if_neg hi] at hv hP
  by_cases hok : bytesVal (clearFlags (split_at b).1).toList < Fp.modulus ∧
      bytesVal (split_at b).2.toList < Fp.modulus
  · rw [if_pos hok] at hv
    cases hv
  rcases not_and_or.mp hok with h | h
  · revert hP
    cases hf : Fp.fromBytesBE (((toBytes b).set! 0 (b[0]'zero_lt_G2_COMPRESSED_LEN &&& 0x1f)).extract 0 48) with
    | error e => intro hP; cases hP
    | ok c => exact absurd hf (fromBytesBE_error e1 h c)
  · revert hP
    cases hf : Fp.fromBytesBE (((toBytes b).set! 0 (b[0]'zero_lt_G2_COMPRESSED_LEN &&& 0x1f)).extract 48 96) with
    | error e =>
      cases Fp.fromBytesBE (((toBytes b).set! 0 (b[0]'zero_lt_G2_COMPRESSED_LEN &&& 0x1f)).extract 0 48) <;>
        intro hP <;> cases hP
    | ok c => exact absurd hf (fromBytesBE_error e0 h c)

theorem decodeLane_ok {b : Vector UInt8 G2_COMPRESSED_LEN}
    (hu : (decodeLane b).undecided = false) (hv : (decodeLane b).invalid = false) :
    ∃ (_ : ¬(b[0]'zero_lt_G2_COMPRESSED_LEN &&& 0x80 = 0))
      (_ : ¬(b[0]'zero_lt_G2_COMPRESSED_LEN &&& 0x40 ≠ 0))
      (_ : bytesVal (clearFlags (split_at b).1).toList < Fp.modulus)
      (_ : bytesVal (split_at b).2.toList < Fp.modulus),
      decodeLane b = ⟨bytesVal (split_at b).2.toList, bytesVal (clearFlags (split_at b).1).toList,
        decide (b[0]'zero_lt_G2_COMPRESSED_LEN &&& 0x20 ≠ 0), false, false⟩ := by
  unfold decodeLane at hu hv ⊢
  dsimp only at hu hv ⊢
  by_cases hc : b[0]'zero_lt_G2_COMPRESSED_LEN &&& 0x80 = 0
  · rw [if_pos hc] at hv
    cases hv
  rw [if_neg hc] at hu hv ⊢
  by_cases hi : b[0]'zero_lt_G2_COMPRESSED_LEN &&& 0x40 ≠ 0
  · rw [if_pos hi] at hu
    cases hu
  rw [if_neg hi] at hv ⊢
  by_cases hok : bytesVal (clearFlags (split_at b).1).toList < Fp.modulus ∧
      bytesVal (split_at b).2.toList < Fp.modulus
  · rw [if_pos hok]
    exact ⟨hc, hi, hok.1, hok.2, rfl⟩
  · rw [if_neg hok] at hv
    cases hv

theorem fp_mk_eq_natCast {v : ℕ} (h : v < Fp.modulus) :
    ((⟨v, h⟩ : Fp) : ZMod Fp.modulus) = (v : ZMod Fp.modulus) :=
  ZMod.val_injective (n := Fp.modulus) (a₁ := ⟨v, h⟩) (a₂ := (v : ZMod Fp.modulus))
    (ZMod.val_cast_of_lt h).symm

end DecompressG2

namespace Kernel

/-! ## One lane of `decompress` over the field

These restate one lane of `decompress` without its early returns, from that lane's bytes alone.
-/

/-- The lane's x, from its decoded coordinates. -/
noncomputable def laneX (b : Vector UInt8 G2_COMPRESSED_LEN) : Fp2Field :=
  ⟨(decodeLane b).x0, (decodeLane b).x1⟩

/-- The lane's y: the root of x³ + b′ that the sign flag names. -/
noncomputable def laneY (b : Vector UInt8 G2_COMPRESSED_LEN) : Fp2Field :=
  selectRoot (sqrt (rhs (laneX b))).1 (decodeLane b).largerRoot

/-- Bit `on_curve`: the lane decodes and x³ + b′ has a root. -/
noncomputable def laneOnCurve (b : Vector UInt8 G2_COMPRESSED_LEN) : Bool :=
  (sqrt (rhs (laneX b))).2 && !((decodeLane b).invalid || (decodeLane b).undecided)

/-- Bit `undecided`: the infinity encoding, or a curve point whose chain met an exception. -/
noncomputable def laneUndecided (b : Vector UInt8 G2_COMPRESSED_LEN) : Bool :=
  (decodeLane b).undecided || ((scottMembership (laneX b) (laneY b)).2 && laneOnCurve b)

/-- Bit `valid`: a decided curve point that passes the comparison. -/
noncomputable def laneValid (b : Vector UInt8 G2_COMPRESSED_LEN) : Bool :=
  (scottMembership (laneX b) (laneY b)).1 && laneOnCurve b && !laneUndecided b

/-- On a lane that is not undecided, `on_curve` is set exactly when `G2.uncompress` succeeds,
and then the lane's point is the spec's. -/
theorem laneOnCurve_iff {b : Vector UInt8 G2_COMPRESSED_LEN} (hu : laneUndecided b = false) :
    (laneOnCurve b = true ↔ ∃ P, G2.uncompress (toBytes b) = .ok P) ∧
      ∀ P, G2.uncompress (toBytes b) = .ok P →
        P.z = Fp2.one ∧ Fp2.toField P.x = laneX b ∧ Fp2.toField P.y = laneY b := by
  have hdu : (decodeLane b).undecided = false := by
    rw [laneUndecided, Bool.or_eq_false_iff] at hu
    exact hu.1
  by_cases hinv : (decodeLane b).invalid = true
  · have hfail := uncompress_of_invalid hdu hinv
    have hon : laneOnCurve b = false := by
      rw [laneOnCurve, hinv, Bool.true_or, Bool.not_true, Bool.and_false]
    refine ⟨⟨fun h => ?_, fun h => ?_⟩, fun P hP => absurd hP (hfail P)⟩
    · rw [hon] at h
      cases h
    · obtain ⟨P, hP⟩ := h
      exact absurd hP (hfail P)
  obtain ⟨hc, hi, h1, h0, hd⟩ := decodeLane_ok hdu (Bool.eq_false_iff.mpr hinv)
  have hspec := uncompress_eq hc hi h1 h0
  dsimp only at hspec
  set x : Fp2 := ⟨⟨_, h0⟩, ⟨_, h1⟩⟩ with hx
  have hxf : Fp2.toField x = laneX b := by
    rw [hx, Fp2.toField_mk, fp_mk_eq_natCast, fp_mk_eq_natCast, laneX, hd]
  have hrhs := rhs_toField x
  rw [hxf] at hrhs
  rw [laneOnCurve, laneY, ← hrhs, hd]
  dsimp only
  cases hsq : Fp2.sqrt (x * x * x + G2.bTwist) with
  | error e =>
    rw [hsq] at hspec
    dsimp only at hspec
    rw [sqrt_fails hsq]
    refine ⟨⟨fun h => absurd h (by decide), fun h => ?_⟩, fun P hP => ?_⟩
    · obtain ⟨P, hP⟩ := h
      rw [hspec] at hP
      cases hP
    rw [hspec] at hP
    cases hP
  | ok yPos =>
    rw [hsq] at hspec
    dsimp only at hspec
    obtain ⟨hhas, hsel⟩ := sqrt_agrees hsq (decide (b[0]'zero_lt_G2_COMPRESSED_LEN &&& 0x20 ≠ 0))
    rw [hhas]
    refine ⟨⟨fun _ => ?_, fun _ => rfl⟩, fun P hP => ?_⟩
    · exact ⟨_, hspec⟩
    · rw [hspec] at hP
      injection hP with hP
      subst hP
      exact ⟨rfl, hxf, hsel.symm⟩

theorem laneOnCurve_nonsingular {b : Vector UInt8 G2_COMPRESSED_LEN} (h : laneOnCurve b = true) :
    E'.Nonsingular (laneX b) (laneY b) := by
  rw [laneOnCurve, Bool.and_eq_true] at h
  have hsq := sqrt_fst_sq h.1
  rw [E'.nonsingular_iff, laneY]
  generalize laneX b = x at hsq ⊢
  have hsel : (selectRoot (sqrt (rhs x)).1 (decodeLane b).largerRoot) ^ 2 =
      (sqrt (rhs x)).1 ^ 2 := by
    unfold selectRoot
    split <;> ring
  rw [hsel, hsq, rhs, bTwist]
  ring

/-- On a lane that is not undecided, `valid` is set exactly when `G2.uncompress` succeeds with a
point P such that ψ(P) = [z]P, P read through `G2.toPoint`. -/
theorem laneValid_iff {b : Vector UInt8 G2_COMPRESSED_LEN} (hu : laneUndecided b = false) :
    laneValid b = true ↔
      ∃ P, G2.uncompress (toBytes b) = .ok P ∧ psi (G2.toPoint P) = z • G2.toPoint P := by
  obtain ⟨hon, hpt⟩ := laneOnCurve_iff hu
  have hpoint {P : G2} (hP : G2.uncompress (toBytes b) = .ok P) :
      ∃ h, G2.toPoint P = .some (laneX b) (laneY b) h := by
    obtain ⟨hz, hx, hy⟩ := hpt P hP
    have hns := laneOnCurve_nonsingular (hon.mpr ⟨P, hP⟩)
    refine ⟨hns, ?_⟩
    obtain ⟨px, py, pz⟩ := P
    simp only at hz hx hy
    subst hz
    rw [G2.toPoint_mk_one (hx ▸ hy ▸ hns)]
    simp only [hx, hy]
  have hm2 (hc : laneOnCurve b = true) : (scottMembership (laneX b) (laneY b)).2 = false := by
    have := hu
    rw [laneUndecided, hc, Bool.and_true, Bool.or_eq_false_iff] at this
    exact this.2
  rw [laneValid, hu, Bool.not_false, Bool.and_true]
  constructor
  · intro hval
    rw [Bool.and_eq_true] at hval
    obtain ⟨hm, hc⟩ := hval
    obtain ⟨P, hP⟩ := hon.mp hc
    obtain ⟨hns, hpP⟩ := hpoint hP
    rw [scottMembership_spec hns (hm2 hc), decide_eq_true_iff] at hm
    exact ⟨P, hP, by rw [hpP]; exact hm⟩
  · rintro ⟨P, hP, hψ⟩
    have hc := hon.mpr ⟨P, hP⟩
    obtain ⟨hns, hpP⟩ := hpoint hP
    rw [hc, scottMembership_spec hns (hm2 hc), ← hpP, decide_eq_true hψ]
    rfl

end Kernel

namespace DecompressG2

open Kernel

/-! ## blst's limbs -/

/-- blst's six words of a field element: its Montgomery form with R = 2^384, little-endian. -/
def blstFp (a : ZMod Fp.modulus) : BlstFp :=
  ⟨.ofFn fun j => .ofNat ((a * 2 ^ 384).val / 2 ^ (64 * j.val))⟩

/-- A point as `blst_p2_affine`: x before y, and c0 before c1 in each. -/
def blstPoint (x y : Fp2Field) : BlstP2Affine :=
  { x := ⟨#v[blstFp x.re, blstFp x.im]⟩, y := ⟨#v[blstFp y.re, blstFp y.im]⟩ }

/-- The spec's point `P = (x, y, 1)` as `blst_p2_affine`. -/
def blstLimbs (P : G2) : BlstP2Affine := blstPoint (Fp2.toField P.x) (Fp2.toField P.y)

set_option exponentiation.threshold 400 in
theorem val64_blstFp (a : ZMod Fp.modulus) : val64 (blstFp a).l = (a * 2 ^ 384).val := by
  have hv : (a * 2 ^ 384).val < 2 ^ 384 := lt_trans (ZMod.val_lt _) (by have := p_lt; omega)
  simp only [blstFp, val64_eq, Vector.getElem_ofFn, UInt64.toNat_ofNat']
  generalize (a * 2 ^ 384).val = v at hv ⊢
  norm_num
  omega

theorem blstFp_eq {w : Vector UInt64 6} {a : ZMod Fp.modulus} (h : val64 w = (a * 2 ^ 384).val) :
    (⟨w⟩ : BlstFp) = blstFp a := by
  rw [eq_of_val64_eq (h.trans (val64_blstFp a).symm)]

/-! ## The stages of `decompress` on one lane -/

/-- The x that `decompress` computes from its decoded lanes. -/
def xOf (D : Decoded) : Fp2x8 := ⟨Fp8.from_plain D.x0, Fp8.from_plain D.x1⟩

/-- x³ + b′ as `decompress` computes it. -/
def rhsOf (X : Fp2x8) : Fp2x8 :=
  (X.square.mul X).add ⟨Fp8.splat_limbs (.ofList FOUR_MONT), Fp8.splat_limbs (.ofList FOUR_MONT)⟩

theorem lane_x (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) (l : Fin 8) :
    (xOf (decode inputs)).Holds l (laneX inputs[l]) := by
  have hd := decode_holds inputs l
  exact ⟨(Fp8.holds_from_plain hd.inv0).of_eq (by rw [hd.val0]; rfl),
    (Fp8.holds_from_plain hd.inv1).of_eq (by rw [hd.val1]; rfl)⟩

theorem lane_rhs {x : Fp2x8} {l : Fin 8} {v : Fp2Field} (hx : x.Holds l v) :
    (rhsOf x).Holds l (rhs v) := by
  have h4 := (Fp8.holds_splat_limbs inv_ofList_FOUR_MONT l).of_eq decode_ofList_FOUR_MONT
  exact ((hx.square.mul hx).add (y := ⟨_, _⟩) (w := ⟨4, 4⟩) ⟨h4, h4⟩).of_eq rfl

/-- The loop that writes `points`, with `f lane` the point it writes at `lane`. -/
def pointsLoop (f : Fin 8 → BlstP2Affine) (ls : List (Fin 8)) (b : Batch) : Batch :=
  ls.foldl (fun batch (lane : Fin 8) => { batch with points := batch.points.set lane (f lane) }) b

theorem pointsLoop_masks (f : Fin 8 → BlstP2Affine) : ∀ (ls : List (Fin 8)) (b : Batch),
    (pointsLoop f ls b).on_curve = b.on_curve ∧ (pointsLoop f ls b).valid = b.valid ∧
      (pointsLoop f ls b).undecided = b.undecided
  | [], _ => ⟨rfl, rfl, rfl⟩
  | i :: ls, b => pointsLoop_masks f ls { b with points := b.points.set i (f i) }

theorem pointsLoop_points (f : Fin 8 → BlstP2Affine) (l : Fin 8) : ∀ (ls : List (Fin 8)) (b : Batch),
    (pointsLoop f ls b).points[l] = if l ∈ ls then f l else b.points[l]
  | [], _ => by simp [pointsLoop]
  | i :: ls, b => by
    rw [pointsLoop, List.foldl_cons, ← pointsLoop, pointsLoop_points f l ls]
    by_cases hlr : l ∈ ls
    · simp [hlr]
    · by_cases hli : l = i
      · subst hli
        simp
      · have : (i : ℕ) ≠ l := fun h => hli (Fin.ext h).symm
        simp [hlr, hli, Vector.getElem_set_ne _ _ this]

/-- `decompress` after its root, without the two early returns: the decoded lanes `D`, x `X` and
the root `(root, has)` of x³ + b′ given. -/
def tailFull (D : Decoded) (X root : Fp2x8) (has : Mmask8) : Batch :=
  let batch : Batch := {
    points := .replicate 8 default,
    on_curve := 0,
    valid := 0,
    undecided := D.undecided }
  let decodable := ~~~(D.invalid ||| D.undecided)
  let batch := { batch with on_curve := has &&& decodable }
  let flip := root.is_larger_root_mask ^^^ D.larger_root
  let y := Fp2x8.select flip root root.neg
  let membership := G2x8.scott_membership X y
  let batch := { batch with undecided := batch.undecided ||| (membership.undecided &&& batch.on_curve) }
  let batch := { batch with valid := membership.members &&& batch.on_curve &&& ~~~batch.undecided }
  let (x0, x1) := (X.c0.to_blst_limbs, X.c1.to_blst_limbs)
  let (y0, y1) := (y.c0.to_blst_limbs, y.c1.to_blst_limbs)
  (List.finRange 8).foldl (init := batch) fun batch (lane : Fin 8) =>
    { batch with points := batch.points.set lane {
        x := { fp := #v[{ l := x0[lane] }, { l := x1[lane] }] },
        y := { fp := #v[{ l := y0[lane] }, { l := y1[lane] }] } } }

/-- `decompress` after its root, with its two early returns. -/
def tail (D : Decoded) (X root : Fp2x8) (has : Mmask8) : Batch :=
  let batch : Batch := {
    points := .replicate 8 default,
    on_curve := 0,
    valid := 0,
    undecided := D.undecided }
  let decodable := ~~~(D.invalid ||| D.undecided)
  if decodable = 0 then batch else
  let batch := { batch with on_curve := has &&& decodable }
  if batch.on_curve = 0 then batch else
  tailFull D X root has

/-- `decompress` without its two early returns. -/
def decompressFull (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) : Batch :=
  tailFull (decode inputs) (xOf (decode inputs)) (rhsOf (xOf (decode inputs))).sqrt.1
    (rhsOf (xOf (decode inputs))).sqrt.2

/-- The verdicts and points of one lane, as `Kernel`'s lane functions give them. -/
structure LaneVerdicts (batch : Batch) (b : Vector UInt8 G2_COMPRESSED_LEN) (l : Fin 8) : Prop where
  undecided : batch.undecided.toNat.testBit l = laneUndecided b
  onCurve : batch.on_curve.toNat.testBit l = laneOnCurve b
  valid : batch.valid.toNat.testBit l = laneValid b
  points : laneOnCurve b = true → batch.points[l] = blstPoint (laneX b) (laneY b)

theorem tailFull_lane {D : Decoded} {X root : Fp2x8} {has : Mmask8}
    {b : Vector UInt8 G2_COMPRESSED_LEN} {l : Fin 8} (hd : (decodeLane b).Holds D l)
    (hx : X.Holds l (laneX b)) (hroot : root.Holds l (sqrt (rhs (laneX b))).1)
    (hhas : has.toNat.testBit l = (sqrt (rhs (laneX b))).2) :
    LaneVerdicts (tailFull D X root has) b l := by
  unfold tailFull
  dsimp only
  have hy := (hroot.select (root.is_larger_root_mask ^^^ D.larger_root) hroot.neg).of_eq
    (w := laneY b) (by
      rw [Mmask8.testBit_xor, hroot.testBit_is_larger_root_mask, hd.largerRoot, laneY, selectRoot])
  generalize Fp2x8.select (root.is_larger_root_mask ^^^ D.larger_root) root root.neg = Y at hy ⊢
  obtain ⟨hmm, hmu⟩ := G2x8.holds_scott_membership hx hy
  generalize G2x8.scott_membership X Y = M at hmm hmu ⊢
  have honc : (has &&& ~~~(D.invalid ||| D.undecided)).toNat.testBit l = laneOnCurve b := by
    rw [Mmask8.testBit_and, hhas, Mmask8.testBit_not, Mmask8.testBit_or, hd.invalid, hd.undecided,
      laneOnCurve]
  have hmasks := pointsLoop_masks (fun lane => {
      x := { fp := #v[{ l := X.c0.to_blst_limbs[lane] }, { l := X.c1.to_blst_limbs[lane] }] },
      y := { fp := #v[{ l := Y.c0.to_blst_limbs[lane] }, { l := Y.c1.to_blst_limbs[lane] }] } })
    (List.finRange 8) (Batch.mk (Vector.replicate 8 default) (has &&& ~~~(D.invalid ||| D.undecided))
      (M.members &&& (has &&& ~~~(D.invalid ||| D.undecided)) &&&
        ~~~(D.undecided ||| M.undecided &&& (has &&& ~~~(D.invalid ||| D.undecided))))
      (D.undecided ||| M.undecided &&& (has &&& ~~~(D.invalid ||| D.undecided))))
  have hpts := pointsLoop_points (fun lane => {
      x := { fp := #v[{ l := X.c0.to_blst_limbs[lane] }, { l := X.c1.to_blst_limbs[lane] }] },
      y := { fp := #v[{ l := Y.c0.to_blst_limbs[lane] }, { l := Y.c1.to_blst_limbs[lane] }] } })
    l (List.finRange 8) (Batch.mk (Vector.replicate 8 default) (has &&& ~~~(D.invalid ||| D.undecided))
      (M.members &&& (has &&& ~~~(D.invalid ||| D.undecided)) &&&
        ~~~(D.undecided ||| M.undecided &&& (has &&& ~~~(D.invalid ||| D.undecided))))
      (D.undecided ||| M.undecided &&& (has &&& ~~~(D.invalid ||| D.undecided))))
  rw [if_pos (List.mem_finRange l)] at hpts
  simp only [pointsLoop] at hmasks hpts
  have hund : (D.undecided ||| M.undecided &&& (has &&& ~~~(D.invalid ||| D.undecided))).toNat.testBit
      l = laneUndecided b := by
    rw [Mmask8.testBit_or, Mmask8.testBit_and, hd.undecided, hmu, honc, laneUndecided]
  refine ⟨?_, ?_, ?_, fun _ => ?_⟩
  · rw [hmasks.2.2, hund]
  · rw [hmasks.1, honc]
  · rw [hmasks.2.1, Mmask8.testBit_and, Mmask8.testBit_and, Mmask8.testBit_not, hund, hmm, honc,
      laneValid]
  · rw [hpts]
    simp only [blstPoint]
    rw [← blstFp_eq hx.re.val64_to_blst_limbs, ← blstFp_eq hx.im.val64_to_blst_limbs,
      ← blstFp_eq hy.re.val64_to_blst_limbs, ← blstFp_eq hy.im.val64_to_blst_limbs]

theorem tail_lane {D : Decoded} {X root : Fp2x8} {has : Mmask8}
    {b : Vector UInt8 G2_COMPRESSED_LEN} {l : Fin 8} (hd : (decodeLane b).Holds D l)
    (hx : X.Holds l (laneX b)) (hroot : root.Holds l (sqrt (rhs (laneX b))).1)
    (hhas : has.toNat.testBit l = (sqrt (rhs (laneX b))).2) :
    LaneVerdicts (tail D X root has) b l := by
  have hdec : (~~~(D.invalid ||| D.undecided)).toNat.testBit l =
      !((decodeLane b).invalid || (decodeLane b).undecided) := by
    rw [Mmask8.testBit_not, Mmask8.testBit_or, hd.invalid, hd.undecided]
  have honc : (has &&& ~~~(D.invalid ||| D.undecided)).toNat.testBit l = laneOnCurve b := by
    rw [Mmask8.testBit_and, hhas, hdec, laneOnCurve]
  unfold tail
  dsimp only
  split_ifs with h1 h2
  · have hon : laneOnCurve b = false := by
      rw [laneOnCurve, ← hdec, Mmask8.testBit_of_eq_zero h1, Bool.and_false]
    refine ⟨?_, ?_, ?_, fun h => absurd h (by rw [hon]; decide)⟩
    · rw [laneUndecided, hon, Bool.and_false, Bool.or_false, hd.undecided]
    · rw [hon, Mmask8.testBit_zero]
    · rw [laneValid, hon, Bool.and_false, Bool.false_and, Mmask8.testBit_zero]
  · have hon : laneOnCurve b = false := by
      rw [← honc, Mmask8.testBit_of_eq_zero h2]
    refine ⟨?_, ?_, ?_, fun h => absurd h (by rw [hon]; decide)⟩
    · rw [laneUndecided, hon, Bool.and_false, Bool.or_false, hd.undecided]
    · exact honc
    · rw [laneValid, hon, Bool.and_false, Bool.false_and, Mmask8.testBit_zero]
  · exact tailFull_lane hd hx hroot hhas

theorem decompress_eq (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) :
    decompress inputs = tail (decode inputs) (xOf (decode inputs)) (rhsOf (xOf (decode inputs))).sqrt.1
      (rhsOf (xOf (decode inputs))).sqrt.2 := rfl

/-- Each lane of `decompress` gives the verdicts and the point of `Kernel`'s
lane functions on that lane's bytes. -/
theorem decompress_lane (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) (l : Fin 8) :
    LaneVerdicts (decompress inputs) inputs[l] l := by
  have hx := lane_x inputs l
  obtain ⟨hroot, hhas⟩ := (lane_rhs hx).sqrt
  rw [decompress_eq]
  exact tail_lane (decode_holds inputs l) hx hroot hhas

/-- The same for `decompress` without its early returns. -/
theorem decompressFull_lane (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) (l : Fin 8) :
    LaneVerdicts (decompressFull inputs) inputs[l] l := by
  have hx := lane_x inputs l
  obtain ⟨hroot, hhas⟩ := (lane_rhs hx).sqrt
  exact tailFull_lane (decode_holds inputs l) hx hroot hhas

/-! ## The per-lane theorems -/

/-- On a lane that is not undecided, `on_curve` is set exactly when `G2.uncompress` of the
lane's bytes succeeds, and then `points` holds that point in blst's limbs. -/
theorem decompress_onCurve (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) (l : Fin 8)
    (hu : (decompress inputs).undecided.toNat.testBit l = false) :
    ((decompress inputs).on_curve.toNat.testBit l = true ↔
        ∃ P, G2.uncompress (toBytes inputs[l]) = .ok P) ∧
      ∀ P, G2.uncompress (toBytes inputs[l]) = .ok P → (decompress inputs).points[l] = blstLimbs P := by
  have hv := decompress_lane inputs l
  rw [hv.undecided] at hu
  obtain ⟨hon, hpt⟩ := laneOnCurve_iff hu
  refine ⟨by rw [hv.onCurve]; exact hon, fun P hP => ?_⟩
  obtain ⟨-, hx, hy⟩ := hpt P hP
  rw [hv.points (hon.mpr ⟨P, hP⟩), blstLimbs, hx, hy]

/-- On a lane that is not undecided, `valid` is set exactly when `G2.uncompress` of the lane's
bytes succeeds with a point P such that ψ(P) = [z]P, P read through `G2.toPoint`. -/
theorem decompress_valid (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) (l : Fin 8)
    (hu : (decompress inputs).undecided.toNat.testBit l = false) :
    (decompress inputs).valid.toNat.testBit l = true ↔
      ∃ P, G2.uncompress (toBytes inputs[l]) = .ok P ∧ psi (G2.toPoint P) = z • G2.toPoint P := by
  have hv := decompress_lane inputs l
  rw [hv.undecided] at hu
  rw [hv.valid]
  exact laneValid_iff hu

/-- A valid lane is not undecided. -/
theorem decompress_undecided_of_valid {inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8}
    {l : Fin 8} (h : (decompress inputs).valid.toNat.testBit l = true) :
    (decompress inputs).undecided.toNat.testBit l = false := by
  have hv := decompress_lane inputs l
  rw [hv.valid, laneValid, Bool.and_eq_true, Bool.not_eq_true'] at h
  rw [hv.undecided]
  exact h.2

/-- A lane's verdicts, and its point where it is on the curve, depend only on its own bytes. -/
theorem decompress_lane_independent {inputs inputs' : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8}
    {l : Fin 8} (h : inputs[l] = inputs'[l]) :
    (decompress inputs).undecided.toNat.testBit l = (decompress inputs').undecided.toNat.testBit l ∧
      (decompress inputs).on_curve.toNat.testBit l = (decompress inputs').on_curve.toNat.testBit l ∧
      (decompress inputs).valid.toNat.testBit l = (decompress inputs').valid.toNat.testBit l ∧
      ((decompress inputs).on_curve.toNat.testBit l = true →
        (decompress inputs).points[l] = (decompress inputs').points[l]) := by
  have hv := decompress_lane inputs l
  have hv' := decompress_lane inputs' l
  rw [← h] at hv'
  refine ⟨hv.undecided.trans hv'.undecided.symm, hv.onCurve.trans hv'.onCurve.symm,
    hv.valid.trans hv'.valid.symm, fun hc => ?_⟩
  rw [hv.onCurve] at hc
  rw [hv.points hc, hv'.points hc]

/-- The two early returns leave each lane's verdicts, and its point where it is on the curve,
as the full computation gives them. -/
theorem decompress_eq_full (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) (l : Fin 8) :
    (decompress inputs).undecided.toNat.testBit l = (decompressFull inputs).undecided.toNat.testBit l ∧
      (decompress inputs).on_curve.toNat.testBit l =
        (decompressFull inputs).on_curve.toNat.testBit l ∧
      (decompress inputs).valid.toNat.testBit l = (decompressFull inputs).valid.toNat.testBit l ∧
      ((decompress inputs).on_curve.toNat.testBit l = true →
        (decompress inputs).points[l] = (decompressFull inputs).points[l]) := by
  have hv := decompress_lane inputs l
  have hf := decompressFull_lane inputs l
  refine ⟨hv.undecided.trans hf.undecided.symm, hv.onCurve.trans hf.onCurve.symm,
    hv.valid.trans hf.valid.symm, fun hc => ?_⟩
  rw [hv.onCurve] at hc
  rw [hv.points hc, hf.points hc]

end DecompressG2

end LeanBlsSimd
