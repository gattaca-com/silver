import LeanBlsSimd.Pairing.LaneTable

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.Pairing.LaneLines

open LaneTower

set_option maxRecDepth 4000

def packedFactors (v : Factors) : V F :=
  ![v 0 1, v 0 1, v 0 2, v 0 2, v 1 1, v 1 1, v 1 2, v 1 2]

def products (step : Fin 68) (v : Factors) : V F :=
  fun l => (fun (a b : F) => a * b) (Kzg.pairingLineValue step l) (packedFactors v l)

def lineIndices (c pair : Fin 2) : Array I64 8#usize :=
  if c = 0 then pairing.LINE_C0.val[pair.val]'(by simp; omega)
  else pairing.LINE_C1.val[pair.val]'(by simp; omega)

def lineLanes (step : Fin 68) (pair : Fin 2) (v : Factors) : LaneTower.P F :=
  (![v pair 0, (coefficient step pair 0).c0 * v pair 1,
      (coefficient step pair 1).c0 * v pair 2, v pair 0, v pair 0, v pair 0, v pair 0, v pair 0],
   ![0, (coefficient step pair 0).c1 * v pair 1,
      (coefficient step pair 1).c1 * v pair 2, 0, 0, 0, 0, 0])

theorem line_shuffle (step : Fin 68) (pair : Fin 2) (v : Factors) (z : V F)
    (hz0 : z 0 = v 0 0) (hz1 : z 1 = v 1 0) :
    (shuffle (lineIndices 0 pair) z (products step v),
     shuffle (lineIndices 1 pair) (fun _ => 0) (products step v)) = lineLanes step pair v := by
  simp only [lineIndices, pairing.LINE_C0, pairing.LINE_C1]
  apply Prod.ext <;> funext l <;> fin_cases pair <;> fin_cases l
  all_goals first | exact hz0 | exact hz1 | rfl

theorem line_value (step : Fin 68) (pair : Fin 2) (v : Factors) :
    value (sparseLine (lineLanes step pair v)) = factorLine step pair v := by
  have hm (a : Bls.Fp2) (b : Fp) : a * Bls.Fp2.ofFp b = ⟨a.c0 * b, a.c1 * b⟩ := by
    let x : F := a.c0
    let y : F := a.c1
    let z : F := b
    apply fp2_ext
    · change x * z - y * 0 = x * z
      simp
    · change x * 0 + y * z = y * z
      simp
  simp only [factorLine, hm]
  apply fp12_ext <;> apply fp6_ext <;> apply fp2_ext <;> rfl

theorem line_refines {x z : fp8.Fp8} (step : Fin 68) (pair : Fin 2) (v : Factors) (zs : V F)
    (hx : Normal (fun _ => 2) x (products step v))
    (hz : Normal (fun _ => 2) z zs) (hz0 : zs 0 = v 0 0) (hz1 : zs 1 = v 1 0) :
    ∃ out, pairing.line x z (UScalar.ofNatCore pair.val (by have := two_pow_32_le_usize; omega)) = ok out ∧
      Strict2 256 out (lineLanes step pair v) := by
  let k : Usize := UScalar.ofNatCore pair.val (by have := two_pow_32_le_usize; omega)
  obtain ⟨a, ha, ra⟩ := normal_permute2 (lineIndices 0 pair) hz hx
  obtain ⟨zero, hzero, rzero⟩ := raw_zero
  obtain ⟨b, hb, rb⟩ := normal_permute2 (lineIndices 1 pair) rzero hx
  have h0 : shuffle (lineIndices 0 pair) (fun _ => 2) (fun _ => 2) = fun _ => 2 := by
    funext l; simp [shuffle]
  have h1 : ∀ l, shuffle (lineIndices 1 pair) (fun _ => 0) (fun _ => 2) l < 256 := by
    intro l; simp [shuffle]; split_ifs <;> decide
  refine ⟨⟨a, b⟩, ?_, ?_⟩
  · change pairing.line x z k = ok ⟨a, b⟩
    simp only [pairing.line,
      index_usize_eq pairing.LINE_C0 k (by change pair.val < 2; omega),
      index_usize_eq pairing.LINE_C1 k (by change pair.val < 2; omega), bind_tc_ok]
    change (do
      let a ← fp8.Fp8.permute2 z x (lineIndices 0 pair)
      let zero ← fp8.Fp8.zero
      let b ← fp8.Fp8.permute2 zero x (lineIndices 1 pair)
      ok (⟨a, b⟩ : fp2x8.Fp2x8)) = _
    simp only [ha, hzero, hb, bind_tc_ok]
  · rw [← line_shuffle step pair v zs hz0 hz1]
    constructor
    · intro l
      rw [h0] at ra
      exact (ra l).boundRep (by change 2 < 256; decide)
    · intro l
      exact (rb l).boundRep (h1 l)

end LeanBlsSimd.Pairing.LaneLines
