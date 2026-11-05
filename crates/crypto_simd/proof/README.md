# Formal proof of BLS decoding and KZG cell operations

One Lean project checks the Charon/Aeneas translation of `silver_crypto_simd`'s G1 and G2 batch decoders, `bls::PairingProduct`, `kzg::CellBatchVerifier` and `kzg::CellExtender`. The IFMA verifier headline uses the proved lane pairing and G1 decoder paths. The general verifier headline assumes scoped blst G1-decoder and pairing laws. The extender needs neither law on either route. `bls::PairingProduct` proves its IFMA lane route and assumes a separate blst law for the rest. Scalar and base-field arithmetic, scalar bytes, both streaming SHA implementations, portable G1 decoding, portable MSM and lane pairing are proved. The [trust list](#what-a-reader-must-trust) explains the connection from generated Lean semantics to Rust.

The BLS proofs cover point decoding and subgroup checks, including the IFMA kernels and Scott criteria. They also cover pairing products. G1 portable decoding is proved by `Portable.Decode.g1_decoder_correct`, which constructs `G1DecoderCorrect`. G2 fallback retains the opaque blst decoder and its explicit agreement premise. Full BLS signature verification is outside the scope. KZG verification and extension include constructors, `Default`, output writes, persistent state and repeated calls.

The project pins upstream `ethereum/EthLib` at `98395150`, with Lean and Mathlib at v4.35.0. Aeneas is pinned to `nightly-2026.10.30-de16f3c`. The extraction includes portable implementations, independent CPU feature observations and separately compiled setup literals. The Lake package is `lean_bls_simd`; its library is `LeanBlsSimd`.

- [What is proved](#what-is-proved): [G1 wrapper](#g1-wrapper), [G2 wrapper](#g2-wrapper), [G2 kernel](#g2-kernel), [pairing products](#pairing-products), [KZG verifier](#kzg-verifier), [KZG extender](#kzg-extender).
- [Using the public results](#using-the-public-results).
- [What a reader must trust](#what-a-reader-must-trust).
- [Reproduction](#reproducing-the-proof-and-checks) and [maintenance](lean/README.md).
- [BLS internals](#bls-proof-internals) and [KZG internals](#kzg-proof-internals).

## What is proved

Both public BLS wrappers require one output slot per input. On unequal lengths, the generated functions return `fail .assertionFailure`; their mismatch theorems do not retain Rust's panic text, `"one verdict slot per input"`.

### G1 wrapper

`UncompressG1.uncompress_in_g1_eq_spec` covers the generated public wrapper, including output writes, portable fallback calls on IFMA and the scoped non-IFMA external operation:

```lean
theorem uncompress_in_g1_eq_spec [RuntimeFeatures] [KzgExternals] [FallbackCorrect]
    (inputs : Slice (Array U8 48#usize)) (out : Slice (Option g1_point.G1Point))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g1 inputs out = ok result ∧
      result.val.length = inputs.val.length ∧
      ∀ i : Fin inputs.val.length,
        result.val[i.val]? = some (specVerdict inputs.val[i.val])
```

An index uses IFMA when SIMD is available, it belongs to a complete eight-input chunk, and its undecided bit is clear. `Portable.Decode.g1_decoder_correct` proves the portable singleton and pair decoders used for undecided IFMA lanes and short tails. Without IFMA, the wrapper calls `KzgExternals.uncompressG1` per input. `UncompressG1.FallbackCorrect` requires exact specification agreement only when `simdAvailable = false`. `uncompress_in_g1_eq_spec_list_ifma` gives the same list result for an arbitrary external dictionary with no agreement law. The compatibility name `uncompress_in_g1_eq_spec_or_blst` carries the same scoped decoder premise.

The G1 specification verdict calls `bytesToKzgProof`, decodes accepted bytes with `G1.uncompress`, and normalizes through `G1.toAffine`. Each coordinate has six little-endian Montgomery words with R = 2^384. Infinity has both coordinates zero. `G1Spec.verdict_some_iff` relates acceptance and exact limbs to `bytesToKzgProof` and successful decoding.

### G2 wrapper

`UncompressG2.uncompress_in_g2_eq_spec_or_blst` covers the generated public wrapper:

```lean
theorem uncompress_in_g2_eq_spec_or_blst [RuntimeFeatures] [BlsExternals]
    (inputs : Slice (Array U8 96#usize)) (out : Slice (Option g2_point.G2Point))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g2 inputs out = ok result ∧
      result.val.length = inputs.val.length ∧
      ∀ i : Fin inputs.val.length,
        result.val[i.val]? = some
          (if usesKernelAt inputs i.val then specVerdict inputs.val[i.val]
           else BlsExternals.uncompressG2 inputs.val[i.val])
```

`usesKernelAt_iff` characterizes the route exactly. SIMD must be available and the index in range. The chunk must have at least three inputs and its lane's undecided bit must be clear. Chunks contain at most eight inputs. A short kernel chunk repeats its last input to fill eight lanes; only the original lanes are written back. Smaller chunks, undecided lanes and calls without SIMD use the same scalar external.

Under `UncompressG2.BlstMatchesSpec`, `uncompress_in_g2_eq_spec_list` returns `inputs.val.map specVerdict`, and `uncompress_in_g2_eq_spec_model_list` expresses the result in model types as `inputs.val.map (G2Spec.verdict ∘ ofArray ofU8)`. The pointwise corollary and `uncompress_in_g2_eq_blst` are also available. The premise requires exact agreement on every 96-byte input, including acceptance, affine limbs and infinity.

`G2Spec.verdict` calls the pinned specification's `G2.uncompress` and `G2.inSubgroup`. Its affine conversion calls `G2.toAffine` before writing the coordinates in blst's layout. `G2Spec.verdict_some_iff` characterizes acceptance and exact limbs. The wrapper's `specVerdict` converts accepted limbs to the generated affine representation. `controls/G2Wrapper.lean` checks canonical infinity's all-zero affine result and uses it to reject scalar externals with wrong verdicts or limbs. The decided-lane bridge `decompress_eq_verdict` uses `G2Spec.blstLimbs_eq_of_z_one` to relate this affine conversion to the kernel's conversion of decoded finite points.

### G2 kernel

`mod.rs` reads three parts of a `Batch`: `undecided`, `valid`, and `points` on valid lanes. The headline theorem, in `lean/LeanBlsSimd/Refines/Complete.lean`, covers exactly those, lane by lane. It is about `silver_crypto_simd.bls.decompress_g2.decompress`, the Lean function that Aeneas generates from the Rust:

```lean
theorem decompress_extracted_eq_spec_complete (inputs : Array (Array U8 96#usize) 8#usize) :
    ∃ batch, silver_crypto_simd.bls.decompress_g2.decompress inputs = ok batch ∧
      (∀ l : Fin 8, (ofBatch batch).undecided.toNat.testBit l = false →
        (if (ofBatch batch).valid.toNat.testBit l then some (ofBatch batch).points[l]
          else none) =
        (match G2.uncompress (toBytes (ofArray (ofArray ofU8) inputs (m := 8))[l]) with
          | .error _ => none
          | .ok P => if G2.inSubgroup P then some (blstLimbs P) else none))
```

The generated `decompress` returns `ok batch` for every input. In Aeneas's semantics, this rules out both a panic and divergence. Agreement with the specification requires a clear `undecided` bit for the lane being checked. The conditional API `decompress_extracted_eq_spec` remains in `Refines/Kernel.lean`; the headline theorem supplies its `ScottComplete` argument using `scott_complete`.

Here `l : Fin 8` selects one of the eight lanes. The expression returns `some point` for an accepted lane and `none` for a rejected lane. On the right, [ethereum/EthLib](https://github.com/ethereum/EthLib) decodes with `G2.uncompress` and checks subgroup membership with `G2.inSubgroup`. These are the signature decoding and subgroup checks used by `coreVerify`. The rest of signature verification validates the public key, hashes the message to G2 and checks a pairing. Those steps are outside this theorem.

The conversions make the representation on each side explicit. `ofArray (ofArray ofU8)` converts Aeneas's input arrays to `Vector`s of bytes. `ofBatch` converts each returned mask through `ofU8` and each point through `ofBlstP2Affine`. `toBytes` passes the lane's 96 bytes unchanged. `blstLimbs P` expresses P's coordinates in blst's `blst_p2_affine` layout.

The left side is how `decompress_g2_chunk` in `mod.rs` reads one lane. `Mmask8.and_one_shiftLeft_ne_zero` shows that its test `mask & (1 << lane) != 0` is `testBit`.

`decompress_extracted_eq_spec_complete` combines two results:

- `decompress_refines`, in `lean/LeanBlsSimd/Refines/DecompressG2.lean`: on every input, the generated `decompress` returns `ok` of the model's result, converted back by `toBatch`. This unconditional equality covers every field, including points on rejected and undecided lanes. The other files in `Refines/` establish the corresponding equalities for the functions it calls.
- `decompress_eq_spec`, in `lean/LeanBlsSimd/Proofs/Kernel.lean`: the same claim about the model's `decompress`, over `Vector`s. Its completeness argument is described in [G2 kernel proof and completeness](#g2-kernel-proof-and-completeness).

### Pairing products

Import `LeanBlsSimd.PairingProduct.Headline`. Its results refine generated `PairingProduct` operations to the pinned executable `EthLib.Cryptography.Bls.pairingCheck`. The declarations use the `LeanBlsSimd.PairingProduct` namespace.

`build` runs the generated default constructor and pushes each supplied pair. The headline covers any list of valid points whose retained length is at most `Usize.max`. Infinity pairs and the empty list are allowed:

```lean
theorem build_is_one_correct [RuntimeFeatures] [PairingExternals]
    (blst : BlstMatchesSpec) (pairs : List pairing_product.AffinePair)
    (valid : ∀ p ∈ pairs, Kzg.G1AffineValid p.p ∧ Kzg.G2AffineValid p.q)
    (room : (pairs.filter finitePair).length ≤ Usize.max) :
    (do let owner ← build pairs; pairing_product.PairingProduct.is_one owner) =
      ok (pairingCheck (pairs.map
        (fun p => (Kzg.g1ReadAffine p.p, Kzg.g2ReadAffine p.q))).toArray)
```

`built_owner_correct` gives the resulting owner and the exact list of retained pairs:

```lean
theorem built_owner_correct [RuntimeFeatures] [PairingExternals]
    (blst : BlstMatchesSpec) (pairs : List pairing_product.AffinePair)
    (valid : ∀ p ∈ pairs, Kzg.G1AffineValid p.p ∧ Kzg.G2AffineValid p.q)
    (room : (pairs.filter finitePair).length ≤ Usize.max) :
    ∃ owner, build pairs = ok owner ∧ owner.pairs.val = pairs.filter finitePair ∧
      pairing_product.PairingProduct.is_one owner =
        ok (pairingCheck (pairs.map
          (fun p => (Kzg.g1ReadAffine p.p, Kzg.g2ReadAffine p.q))).toArray)
```

The fixed-two-pair result compares against both original pairs, including pairs skipped because either point is infinity:

```lean
theorem two_pairs_are_one_correct [RuntimeFeatures] [PairingExternals]
    (blst : BlstMatchesSpec) (first second : g1_point.G1Point × g2_point.G2Point)
    (hp : Kzg.G1AffineValid first.1) (hq : Kzg.G2AffineValid first.2)
    (hp' : Kzg.G1AffineValid second.1) (hq' : Kzg.G2AffineValid second.2) :
    pairing_product.PairingProduct.two_pairs_are_one first second =
      ok (pairingCheck #[(Kzg.g1ReadAffine first.1, Kzg.g2ReadAffine first.2),
        (Kzg.g1ReadAffine second.1, Kzg.g2ReadAffine second.2)])
```

An existing owner's stored pairs must satisfy the validity and finiteness invariant:

```lean
theorem is_one_correct [RuntimeFeatures] [PairingExternals]
    (blst : BlstMatchesSpec) (owner : pairing_product.PairingProduct)
    (valid : ∀ p ∈ owner.pairs.val, Kzg.G1AffineValid p.p ∧ Kzg.G2AffineValid p.q)
    (finite : ∀ p ∈ owner.pairs.val, finitePair p = true) :
    pairing_product.PairingProduct.is_one owner =
      ok (pairingCheck (specPairs (alloc.vec.Vec.deref owner.pairs)))
```

`Kzg.G1AffineValid` and `Kzg.G2AffineValid` require canonical affine coordinates and subgroup membership. The G2 predicate expresses curve membership through decodability. Infinity is valid. The premises are explicit because Aeneas represents `G1Point` and `G2Point` as reducible aliases.

`finitePair` means neither point reads as infinity. Generated `push` skips a pair when either point is infinity. Both build headlines compare against the original unfiltered list because the specification skips infinity pairs. The `room` premise bounds the retained length by `Usize.max`. It does not guarantee successful runtime allocation.

`default_empty`, `with_capacity_empty` and `clear_empty` establish empty storage. `push_refines` describes one push. The public `push_list_refines` describes successive pushes from any owner:

```lean
theorem push_list_refines (pairs : List pairing_product.AffinePair)
    (valid : ∀ p ∈ pairs, Kzg.G1AffineValid p.p ∧ Kzg.G2AffineValid p.q)
    (owner : pairing_product.PairingProduct)
    (room : (owner.pairs.val ++ pairs.filter finitePair).length ≤ Usize.max) :
    ∃ result,
      pairs.foldlM (fun owner pair => pairing_product.PairingProduct.push owner pair.p pair.q) owner =
        ok result ∧ result.pairs.val = owner.pairs.val ++ pairs.filter finitePair
```

Combine its exact storage equation with `is_one_correct` after establishing the owner invariant. `is_one_empty` needs no agreement premise. The generated `is_one` returns `Result Bool` without an updated owner. No scratch-state frame obligation is needed.

The blst route uses a separate `PairingExternals` dictionary. Its agreement law applies to finite canonical subgroup pairs:

```lean
structure BlstMatchesSpec [PairingExternals] : Prop where
  check : ∀ pairs, (∀ pair ∈ pairs.val, Kzg.G1AffineValid pair.p ∧ Kzg.G2AffineValid pair.q) →
    (∀ pair ∈ pairs.val, finitePair pair = true) →
    PairingExternals.check pairs = pairingCheck (specPairs pairs)
```

The law trusts the whole opaque Rust `PairingInputs::blst_is_one` wrapper. This includes the chunk loop, null-padded pointer arrays and accumulator initialization. It also includes `blst_miller_loop_n`, accumulator multiplication, `blst_final_exp` and `blst_fp12_is_one`. The binding assumes termination and no Rust-level failure.

Raw `blst_miller_loop_n` does not skip G2 infinity. For the singleton `(G1 generator, G2 infinity)`, the unfiltered wrapper rejects while the specification accepts. The agreement law applies only after the proved infinity filter. It does not assume agreement on arbitrary unfiltered slices.

The lane proof establishes the variable-Q steps, flags, sequential lane-set products and final-exponentiation verdict without the agreement law. The blst route and the whole-product fallback use that law. The KZG and decoder dependency guards exclude the dictionary and its agreement law.

Random-weight batching, public-key admission and hash-to-G2 correctness are not proved here. Neither is their composition into full signature verification. Hardware support for the selected route remains a runtime obligation. The verdict theorem does not cover route choice, fallback frequency or performance.

`controls/downstream/PairingSmoke.lean` applies the public results with an external defined by the specification. Its concrete list contains a finite setup pair and a pair with only its G2 point at infinity. The example discharges every premise. `controls/pairing-product-mutation-check.py` checks refinement proofs against mutations of generated declarations. The original and reformatted declarations serve as positive controls.

### KZG verifier

Under the scoped decoder law, `LeanBlsSimd.Kzg.verify_eq_spec` proves that the generated constructor succeeds and establishes the invariant. Under the per-state pairing law, every state satisfying the invariant returns the embedded specification's Boolean verdict on every representable input. The next state preserves the invariant and stored curve-work route, including after rejected batches. Specification errors become `false`. These include length mismatches, invalid encodings and out-of-range indices.

```lean
theorem verify_eq_spec [cpu : RuntimeFeatures] [KzgExternals]
    [UncompressG1.FallbackCorrect] :
    ∃ initial, verify.CellBatchVerifier.new = ok initial ∧ StateInvariant initial ∧
      ∀ (v : verify.CellBatchVerifier), StateInvariant v →
      BlstPairing.CorrectFor v.curve_work →
      ∀ (i : Input), i.Representable →
      ∃ (verdict : Bool) (next : verify.CellBatchVerifier),
        i.generated v = ok (verdict, next) ∧ StateInvariant next ∧
        CurveWork.isLanes next.curve_work = CurveWork.isLanes v.curve_work ∧
        Model.rejectErrors i.embeddedSpec = verdict
```

`Kzg.pairing_correct` proves the lane `PairingCorrect` contract. The scalar route uses `Kzg.BlstPairing.CorrectFor` per workspace. Its law covers reduced valid G1 inputs, including infinity, paired with the two fixed KZG G2 points. The wrapper performs Jacobian-to-affine conversion. It filters pairs with either point at infinity.

| Proved contract | Component behavior |
|---|---|
| `PairingCorrect` | The lane pairing function agrees with the two fixed-G2 specification pairings under its point representation. This includes `PAIRING_LINES` encoding the lines of [s^64]G2 and −G2. |

The IFMA headlines `verify_eq_spec_ifma` and `verify_eq_upstream_ifma` require `simdAvailable = true` and a stored lane workspace for each call. They establish that route on construction and preserve it on return. Repeated calls therefore need no blst correctness law. The general headlines cover arbitrary states satisfying the invariant, including mixed interpolation and curve-work routes, under the two scoped laws. No KZG result uses the signature-only opaque G2 decoder.

`RuntimeFeatures` supplies independent `simdAvailable`, `shaAvailable` and `bmi2Available` Booleans. Construction selects the interpolation kernel and the `CurveWork` route from `simdAvailable`. SHA dispatch reads `shaAvailable`, while portable field multiplication can select BMI2 independently. The headlines quantify over any fixed feature assignment. The model covers all four combinations of interpolation and curve-work routes independently of the eight feature assignments. Real execution requires hardware support for every instruction on the selected routes; constructor-produced states align the stored routes with stable CPU observations.

`CurveWork.Scalar` stores portable MSM scratch and scalar words. Pairing uses the extracted G2 literals through blst. `CurveWork.Lanes` uses the fixed lane table, whose 544 coefficient lanes have kernel-checked bounds. `CurveWork.sum_frame` preserves the stored route. No workspace stores a mutable pairing table.

`new_returns_ok` requires the scoped G1-decoder law but no pairing law. `default_eq_new` transfers construction through `Default`. `new_returns_ok_route` characterizes the two stored route choices. `Routes.verify_preserves_routes` preserves them. `StateInvariant` fixes setup, cosets, interpolation tables and buffer lengths while permitting arbitrary curve scratch. `CurveWorkInvariant` is `True` for both variants. The scalar-workspace example in `controls/KzgBlstBoundary.lean` checks mixed-route admissibility using `curveWork_scalar_refinement`. The IFMA headline states its lane-workspace requirement.

`verify_eq_upstream` has the same execution/state conclusion for the upstream `verifyCellKzgProofBatch` action. Its only additional hypothesis is `TrustedSetup.get! = pure embeddedSetup`. The embedded-setup headline has no runtime-loader premise. The G2 setup points are fixed mathematical constants with proved decoding and subgroup certificates. IFMA execution uses the fixed pairing table. Scalar pairing uses the extracted affine G2 literals. Neither calls `uncompress_in_g2_blst`.

#### Input and runtime scope

`Input.Representable` requires each input slice to occupy at most `isize::MAX` bytes. It imposes no application-level batch-size limit. The challenge is streamed: the generated `challenge_in_parts` and portable twin process the header, commitments and cell rows without allocating one concatenated transcript. Their refinements require matching slice lengths for indexing, with no total-transcript-fit or 2^61-byte premise. `CellBatchVerifier.challenge` returns a scalar and leaves the verifier state unchanged.

Aeneas models logical vectors and execution results, not heap availability, allocation failure or the Rust allocator's capacity limits. The headlines establish successful execution in those generated semantics under their premises. They do not establish freedom from every Rust allocation or process-level failure.

### KZG extender

`LeanBlsSimd.Kzg.Extender.compute_eq_spec` covers construction and every call from a state satisfying `Extender.StateInvariant`. `Blob` contains 131072 bytes; `Cells` contains 128 cells of 2048 bytes each. `Canonical blob` means that each of its 4096 big-endian, 32-byte integers is below the scalar-field modulus.

```lean
theorem compute_eq_spec [cpu : RuntimeFeatures] :
    ∃ initial, cell_extender.CellExtender.new = ok initial ∧ StateInvariant initial ∧
      ∀ (v : cell_extender.CellExtender), StateInvariant v →
      ∀ (blob : Blob) (cells : Cells),
      ∃ (verdict : Bool) (next : cell_extender.CellExtender) (out : Cells),
        cell_extender.CellExtender.compute v blob cells = ok (verdict, next, out) ∧
        StateInvariant next ∧
        (verdict = true ↔ Canonical blob) ∧
        (verdict = true →
          (computeCells (arrayBytes blob)).run = pure (.ok (cellBytes out))) ∧
        (verdict = false → ∃ err,
          (computeCells (arrayBytes blob)).run = pure (.error err)) ∧
        (verdict = false → out = cells)
```

Every call returns `ok`. Success writes the specification's exact cell bytes. Rejection agrees with a specification error and leaves all output cells unchanged. The invariant fixes scalar roots, inverse roots, inverse size, shift powers and both scalar scratch-vector lengths. It also fixes the optional kernel's FFT tables, shift multipliers and buffer lengths. It allows scratch contents left by earlier successful or rejected calls.

The headline and constructor have no component-contract premises. Scalar arithmetic and byte conversion are proved for the generated functions. No group, hash, pairing, G1-decoder or runtime setup-loader premise is involved. `Extender.default_eq_new` covers `Default`, `Extender.model_eq_spec` equates the full model result with the upstream action, and `Extender.model_accepts_iff` characterizes canonical input.

`new_dispatch_refinement` proves that construction stores a kernel exactly when `simdAvailable` is true. Each `compute` dispatches on that stored option. The internal kernel computation proves its own arithmetic and canonical byte encoding. The public headline composes the portable scalar proofs with that kernel proof. `scalar_constructor_exists` and `kernel_constructor_exists` prove both constructor routes without component premises.

## Using the public results

### Runtime features and external operations

Supply `[silver_crypto_simd.RuntimeFeatures]` to entry points that observe CPU features. `silver_crypto_simd.bls.BlsExternals` contains only the opaque G2 decoder. G2 wrapper results additionally use that class and, for exact specification equality, `UncompressG2.BlstMatchesSpec`. G1 and KZG consumers do not require it. Their separate `KzgExternals` dictionary supplies G1 decoding and scalar pairing. The generic verifier uses `UncompressG1.FallbackCorrect` and `Kzg.BlstPairing.CorrectFor`. IFMA consumers can use the route-specific corollaries without those laws.

### BLS decoding

Import `LeanBlsSimd.Refines.UncompressG1` for the G1 wrapper:

```lean
theorem uncompress_in_g1_eq_spec_list [RuntimeFeatures] [KzgExternals] [FallbackCorrect]
    (inputs : Slice (Array U8 48#usize))
    (out : Slice (Option g1_point.G1Point))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g1 inputs out = ok result ∧
      result.val = inputs.val.map specVerdict ∧
      ∀ p, some p ∈ result.val → Kzg.G1AffineValid p
```

`specVerdict` converts the G1 specification verdict to an optional affine point in the generated representation. `specVerdict_valid` proves `Kzg.G1AffineValid`: accepted points have canonical coordinates and belong to the curve's subgroup. Aeneas represents both point newtypes as reducible aliases. Validity follows from the decoder proof, not the Lean type alone. Pointwise and model-type list variants carry the same scoped decoder law. `controls/G1Consumer.lean` and the independent `controls/downstream/G1Smoke.lean` check these interfaces across consumer-owned structures, including an IFMA adapter without a blst agreement premise.

Import `LeanBlsSimd.Refines.UncompressG2` for G2. Apply `uncompress_in_g2_eq_spec_list` with `[RuntimeFeatures]`, `[BlsExternals]` and `UncompressG2.BlstMatchesSpec`. The theorem proves `Kzg.G2AffineValid p` for every `some p` in the result. `specVerdict_valid` proves validity for individual accepted verdicts. The predicate requires canonical coordinates and subgroup membership. Curve membership means decodability by `G2.uncompress`. Without the agreement law, `uncompress_in_g2_eq_spec_or_blst` characterizes kernel verdicts and opaque fallback observations. `controls/G2Consumer.lean` and `controls/downstream/G2Smoke.lean` exercise the list interfaces and transport across independent structures.

`LeanBlsSimd.Refines.CheckedPoints` specifies the checked raw-constructor contracts. `g1_from_blst_some_iff` and `g2_from_blst_some_iff` characterize acceptance by the affine validity predicates. Accepted results preserve the input limbs. The contracts require `PointExternals` and `ConstructorsMatchSpec`. Decoder and KZG theorems do not require these premises. Both accessors return the wrapped affine value unchanged.

`LeanBlsSimd.Refines.PointOperations` specifies contracts for hashing to G2, weighted sums and the negated G1 generator. `OperationsMatchSpec` relates these opaque calls to EthLib. It requires canonical subgroup outputs. Weighted sums use packed 64-bit little-endian scalars. Their specification requires valid input points. Hashing uses the caller's DST without augmentation. These assumptions apply only to the operation theorems. Decoder and KZG headlines do not use them.

### KZG verification

Import `LeanBlsSimd.Kzg.Statements` and apply:

```lean
verify_eq_spec
```

Supply the CPU-conditioned decoder law and the pairing premise for each state. Use `verify_eq_spec_ifma` for lane workspaces on IFMA with no blst law. Use `new_returns_ok` for construction alone, or `glue_refinement` for the intermediate model. `verify_eq_upstream` additionally takes the runtime setup-loader hypothesis.

For individual generated calls, import `LeanBlsSimd.Kzg.Refines`:

| Wrapper | Cell interface |
|---|---|
| `decode_cells_refines` | Canonical-decoding verdict on both routes; evaluation-scratch equality when `v.kernel = none`. |
| `interpolation_commitment_refines` | `InterpolationKernel.CellsRep cells evals`, with evaluation-scratch equality conditional on `v.kernel = none`. |
| `pairing_holds_refines` | The same cell relation and conditional scratch premise, with the fixed-target specification pairing verdict. |

`CellsRep` requires matching batch lengths and 64 evaluations per cell. Each 32-byte element must decode canonically through `bytesToBlsField`. The headline derives this relation from successful cell checks and discharges the scratch premise internally.

`Kzg/Lincomb.lean` supplies `verify_lincomb_refinement` and its raw-input variant for `verify.CurveWork.sum`, using the proved portable MSM contract and ordinary-word conversion. Lane-only refinements use proved MSM8. `CurveWork.sum_frame` preserves the stored route while allowing arbitrary scratch. The interpolation adapters specialize these results to the embedded setup.

`controls/downstream/KzgSmoke.lean` applies the general verifier under the scoped blst laws. It applies the extender without component premises. It also checks the cell wrappers, their canonical-cell relation and the conditional scalar-scratch premise. `controls/KzgBlstBoundary.lean` checks IFMA construction and execution with an arbitrary external dictionary.

### Decoder bridge and component proofs

`Kzg/Decoder.lean` proves `specVerdict_eq_bls`: KZG and BLS G1 verdicts agree as optional affine points, including limbs and infinity. The KZG batch adapter composes directly with the shared, proved generated G1 wrapper. There is no copied runtime decoder dictionary at this boundary.

`Kzg.pairing_correct` proves the lane pairing contract for the fixed generated definitions. `FrScalar.fr_correct` proves `FrCorrect`. `FrScalar.fr_bytes_correct` proves `FrBytesCorrect`. Neither scalar law is a consumer premise. The Montgomery invariant bounds every row by `a + r`. Only the first operand must be below `r`; the second may contain any four words. The proof retains the fifth multiply-add word and bounds each division result before eliminating truncation. Exact `frEncode` equalities cover addition, subtraction and multiplication. Byte proofs cover canonical decoding, arbitrary digest reduction, ordinary scalar words and exact big-endian serialization. Canonical decoding rejects `r` itself. Digest reduction preserves the generated operand order, with `R_SQUARED` first.

`Portable/Fp/` proves canonical six-word Montgomery arithmetic at R = 2^384. This covers CIOS multiplication and reduction, modular addition and subtraction, binary inversion, exponentiation and root sign. `Portable.Fp.sqrt_refines` characterizes the generated square-root result using `Kernel.sqrtCandidate`. `DecompressG1.sqrt_eq` relates the model's root choice to `Bls.Fp.sqrt`. The CIOS proof permits any six words in the second operand when the first is canonical. Zero-input inversion follows from `Portable.Fp.inverse_encoded` and the field identity `inv_zero`. `Portable.Fp.batch_inverse_schedule` gives all four outputs using one product inverse. A zero factor makes that product inverse zero, so each output is zero. `controls/PortableFpInverse.lean` checks the zero-input and zero-factor cases. `Portable.Fp.mul_encoded` proves multiplication for either BMI2 observation using the shared `product_encoded` theorem. `controls/PortableFpCorrect.lean` checks both wrappers on the encoded-one fixture.

`Portable/G1/` proves scalar doubling, complete projective and affine addition, and the two-lane formulas and chains. `Kzg.PortableG1.neg_coords` preserves coordinate representations under generated negation. Each exceptional lane is recomputed by the scalar Scott test; an unflagged lane agrees with the complete group operations. `Portable/Decode/` connects flags, canonical x, square root and sign to the encoding verdict. It rejects the order-3 x = 0 and order-2 y = 0 cases and accepts only canonical infinity. G1 uses the proved `G1Spec.scott_sound` and `G1Spec.scott_complete`; G2 retains the proved `scott_complete : ScottComplete`. No public decoder headline takes a Scott-completeness premise. The production extraction includes `G1.from_affine`. Rust's `G1.to_affine` is test-only and absent from that extraction, placing its body outside these generated-function proofs.

`controls/ContractSamples.lean` and `MsmSamples.lean` evaluate generated arithmetic, hashing and MSM against the specification. These `#eval` checks use assertions. They run outside the proof kernel and supply finite evidence.

Samples cover scalar carries and canonical-byte boundaries, reducing 2^256−1, both BMI2 field paths, SHA padding and chunk boundaries, and reusable MSM scratch. Rust pairing tests compare random and infinity cases with a Rust transcription of the specification using blst field arithmetic. Infinity cases cover either sum, both infinity encodings used by the crate, and rejection when the remaining finite pair contributes. The generated-code differential corpus covers G1 decoding.

### KZG cell extension

Import `LeanBlsSimd.Kzg.Extender.Statements` and apply:

```lean
Extender.compute_eq_spec
```

The constructor establishes the invariant, and each returned state preserves it for the next call. The fixed-size blob and cell types supply the byte lengths. `controls/downstream/KzgSmoke.lean` applies construction and execution without component premises.

## What a reader must trust

1. **Lean and dependencies.** Lean v4.35.0's kernel and the three standard axioms: `propext`, `Classical.choice` and `Quot.sound`. `LeanBlsSimd/Axioms.lean` uses `Lean.collectAxioms` on imported library theorems and checked generated definitions. It rejects reported dependencies outside that per-theorem allow-list. `acceptedAxioms` is empty, so reported `sorryAx`, `native_decide` and `bv_decide` dependencies fail. A separate default-target check pins the imported environment's complete axiom-name set. `lake exe cache get` downloads Mathlib `.olean` artifacts, which Lean imports without rechecking their proofs. Building Mathlib from source avoids reliance on those downloaded artifacts.
2. **Specification and mathematics.** Mathlib v4.35.0 and [upstream EthLib at `98395150`](https://github.com/ethereum/EthLib/tree/98395150e9eb6a11fd85022bee7ea9da9a8e3760). This includes field and group laws, decoders, subgroup checks, KZG validation, cell-batch verification and `computeCells`. Their fidelity to Ethereum's requirements remains a trust assumption. Vector agreement gives finite evidence, without proving equivalence to other specifications or the embedded ceremony data's provenance. Manual review connects `G2Spec.verdict` to the private decoding stage of `coreVerify`. Its fixed-size type supplies length 96; it calls `G2.uncompress` and `G2.inSubgroup`, accepting canonical infinity. Public-key validation, hash-to-curve and pairing in full signature verification are outside this proof.
3. **Input and output interpretation.** `ofArray`, `ofU8`, `ofBatch` and the affine conversions preserve bit-vectors, lanes and fields. Coordinates use six little-endian 64-bit Montgomery limbs with R = 2^384; G2 orders c0 before c1 and x before y. G1 and G2 public verdicts normalize through `toAffine`, including all-zero infinity. The G2 kernel conversion reads projective x/y; its bridge to the normalized verdict is proved for decoded finite points with z = 1. KZG's reduced scalar encoding uses four 64-bit Montgomery limbs with R = 2^256. The representation targets blst's 64-bit platform layout.
4. **Extraction and generated-code preparation.** Trust includes Charon's MIR semantics, Aeneas's translation and the [deterministic preparation](#reproducing-the-extraction). Aeneas is `nightly-2026.10.30-de16f3c`, resolved to `de16f3cf877976e966906dc890f63dcb418884fa`. Charon is `373d84044d80f6eb44285c2c349bae1453f5b6ca`, using nightly-2026-09-17 rather than the workspace's Rust 1.91.0. `extract.sh` verifies both checkout pins and the commit identities reported by both binaries. The extraction targets x86_64, including BLS chunk helpers, Fr FFT and verifier MSM8 kernels. Its scalar route is covered; a separate non-x86_64 extraction is not checked. Other target configurations depend on their feature detection and source gating. Exact `--check` reproduction detects drift, without proving the translators correct.
5. **External semantics and bindings.** Aeneas models integers, length-indexed collections, bounds and overflow checks, byte conversions and `partial_fixpoint` loops. Its `Result` is an interaction tree representing returns, visible failure effects and divergence. `Extracted/TypesExternal.lean` and `FunsExternal.lean` bind vector types, AVX-512 and SHA/SSE operations, carry arithmetic, lane extraction and feature detection. They also bind standard-library operations such as `Vec.clear`. These models specify bit patterns and logical contents. Their agreement with hardware, ABI and standard-library behavior remains a trust boundary. Intrinsic controls check concrete cases and selected mutations. The opaque Rust functions below are replaced by hand; extraction does not refine their source. Portable scalar, field, G1, MSM and SHA implementations, plus lane pairing, are present in the extraction.
6. **CPU observations and blst boundaries.** `RuntimeFeatures` supplies independent SIMD, SHA and BMI2 Booleans, fixed for a theorem instance. Arbitrary stored routes need matching hardware support in real execution. `BlsExternals` supplies the signature-only G2 decoder. `UncompressG2.BlstMatchesSpec` is its agreement premise. `KzgExternals` separately supplies G1 decoding and the scalar pairing wrapper. `UncompressG1.FallbackCorrect` requires exact verdicts on every 48-byte input when SIMD is unavailable. The scalar case of `Kzg.BlstPairing.CorrectFor` requires exact verdicts for reduced valid G1 inputs, including infinity, and the two fixed KZG G2 points. These opaque functions return `ok`, so their termination and absence of Rust-level failure are assumed. The IFMA verifier headlines require neither agreement law. The extender calls neither operation.
7. **Signature pairing through blst.** `PairingProduct.BlstMatchesSpec` trusts the whole opaque `PairingInputs::blst_is_one` wrapper on finite canonical subgroup pairs. This includes chunking, null-padded pointers, accumulator setup, multi-Miller calls, multiplication, final exponentiation and the identity test. The binding assumes totality. Raw multi-Miller calls do not skip G2 infinity. The law applies only after the proved filter. KZG and decoder headlines exclude the dictionary and law.
8. **Runtime setup for literal-upstream corollaries.** `verify_eq_upstream`, `verify_eq_upstream_ifma` and `LeanBlsSimd.Kzg.model_eq_spec` require `TrustedSetup.get! = pure embeddedSetup`, including that no importer changes the public `TrustedSetup.globalRef`. The initialized reference and `ST.Prim.Ref.get` are opaque in Lean. The embedded-setup theorem instead uses the explicit value and the proved embedded-byte certificates.

The production import environment declares exactly 15 axioms: 12 Lean core declarations and the three Aeneas declarations below. `LeanBlsSimd/AxiomInventory.lean` pins their names and defining modules for diagnostics. `controls/AxiomInventory.lean` checks the exact name set as a default build target. Both unexpected and missing names fail, so inventory changes require review. The check compares names only, not axiom statements.

`LeanBlsSimd/Aeneas.lean` imports 21 named Aeneas modules. Handwritten modules and prepared extraction use this facade. An Aeneas upgrade that renames or splits a named module breaks the build. The inventory rejects returning axioms outside its pinned set.

Lean core contributes the three standard axioms, `sorryAx` and eight unsafe compiler primitives. Aeneas contributes two test recovery stubs and one Rust contract. They are declared in the environment, but the per-theorem allow-list remains only `propext`, `Classical.choice` and `Quot.sound`.

| Aeneas axiom | Role | Purpose |
|---|---|---|
| `Aeneas.Data.ListN.Test.E2` | Test axiom | Recovery stub from a rejected positivity test. |
| `Aeneas.Data.ListN.Test.E3` | Test axiom | Recovery stub from a rejected positivity test. |
| `Aeneas.Std.core.slice.Slice.get_unchecked_SliceIndexUsizeSlice_spec` | Rust contract | Unchecked-slice indexing specification. |

The guard classifies Silver constants by their defining modules, including private helpers and exposed generated code. It walks their kernel types, bodies and inductive constructors with a visited set, without caching per-constant axiom sets. All authored Silver theorems, including private ones, are roots alongside the checked generated definitions. At foreign constants, the walk uses Lean's exported per-declaration axiom lists. The separate per-theorem `collectAxioms` check also remains active. `GuardImported.lean` checks imported type-only and explicit-constructor cycles through an axiom declared in another Silver module.

Lean 4.35's exported per-declaration axiom lists can omit dependencies reached through type/constructor cycles. A cycle entirely inside a dependency stays outside the direct Silver walk. A pinned Aeneas axiom reached only through such a cycle inside a dependency is not detected by the per-theorem guard. The inventory still checks that its name belongs to the exact declared set. It cannot establish which theorems use an existing pinned axiom. An unchanged name set also cannot reveal changed statements.

Every `--opaque` item in `extract.sh` has this interpretation:

| Rust function | Handwritten interpretation |
|---|---|
| `bls::fp8::lanes` | Bitwise extraction of the eight vector lanes. |
| `ifma_available` | The fixed SIMD Boolean in `RuntimeFeatures`. |
| `sha_available` | The fixed SHA Boolean in `RuntimeFeatures`. |
| `bmi2_available` | The fixed BMI2 Boolean in `RuntimeFeatures`. |
| `bls::uncompress_in_g1_blst` | The non-IFMA G1 observation in `KzgExternals`. |
| `kzg::blst_pairing::pairing_check` | The scalar two-pair wrapper observation in `KzgExternals`, including affine conversion and infinity filtering. |
| `bls::uncompress_in_g2_blst` | The signature decoder observation in `BlsExternals`; excluded from KZG. |
| `bls::pairing_product::PairingInputs::blst_is_one` | `PairingExternals.check` observes the whole wrapper, including chunking, pointer arrays, accumulator setup, Miller products, final exponentiation and the identity test. `PairingProduct.BlstMatchesSpec` assumes total specification agreement on finite canonical subgroup pairs. KZG and decoder headlines do not use it. |
| `G1Point::from_blst`, `G2Point::from_blst` | `PointExternals` supplies raw constructor observations. `ConstructorsMatchSpec` specifies acceptance by `Kzg.G1AffineValid` and `Kzg.G2AffineValid`. For G2, equivalence between decodability and blst's on-curve check is unproved. These blst-backed calls are assumed total. Decoder and KZG theorems do not use them. |
| `G1Point::negative_generator`, `G2Point::hash_to_curve`, both `weighted_sum` methods | `PointOperationExternals` supplies blst observations specified by `OperationsMatchSpec`. Weighted sums assume totality on valid points with eight scalar bytes per point. Other scalar lengths produce assertion failure. Hashing and generator negation are assumed total. |
| `sha256::extensions::load_bytes` | Raw-pointer byte loads replaced by little-endian 32-bit lane packing. |
| `sha256::extensions::load_words` | Raw-pointer word loads replaced by 32-bit lane packing. |
| `sha256::extensions::store_words` | Raw-pointer word stores replaced by 32-bit lane unpacking. |

The three SHA load/store bindings replace Rust source routines, in addition to the intrinsic instruction models.


Compiled Rust additionally depends on the compiler, linking, ABI, CPU detection and hardware. The theorem describes Aeneas execution results. Allocation failures and capacity panics lie outside that claim, as detailed in the KZG runtime scope above. The extender has fixed buffer sizes, but its allocations still rely on the runtime and available memory.

## Reproducing the proof and checks

You need [elan](https://github.com/leanprover/elan). From `lean/`:

```sh
lake exe cache get
lake build
```

`lake exe cache get` fetches Mathlib's prebuilt files; run it from `lean/`. Lean imports those files without rechecking Mathlib's proofs. Building Mathlib from source avoids reliance on those prebuilt artifacts.

`lake build` compiles Aeneas's Lean library and the proof, then runs the axiom guard. The guard rejects proof placeholders in checked dependencies, even if unrelated dependency modules contain them. Default targets include refinement controls, both per-theorem guards and the exact axiom inventory. The inventory reports `axiom inventory: exactly 15 declarations`. Their reports give theorem counts, the generated-entry inventory and `axioms used: [propext, Quot.sound, Classical.choice]`. `lake build --wfail` additionally rejects warnings. CI runs the same default targets with `lake build`; its artifact consumer checks `lake build --no-build`. A cold build also compiles uncached dependencies.

Negative controls check that selected mutations are rejected. Other controls check concrete inputs and the axiom list. Every top-level control must exit 0:

```sh
(
  for f in controls/*.lean; do
    lake env lean -DautoImplicit=false -DrelaxedAutoImplicit=false "$f" || exit 1
  done
)
```

Run the extraction fixtures separately from the Lean control loop:

```sh
python3 -I controls/extraction-check.py
```

After `lake build`, run the source mutation checks. They are development tools for changing proofs or the Rust they refine; CI does not run them. They require `lake` and the compiled project imports:

```sh
python3 -I controls/sha-mutation-check.py
python3 -I controls/decoder-mutation-check.py
python3 -I controls/msm-mutation-check.py
python3 -I controls/tower-mutation-check.py
python3 -I controls/lane-tower-mutation-check.py
python3 -I controls/pairing-table-mutation-check.py
python3 -I controls/pairing-loop-mutation-check.py
python3 -I controls/final-exponent-mutation-check.py
```

Build the independent downstream package from its own root:

```sh
(cd controls/downstream && lake update && lake build)
```

The Lean side of the vector test, also from `lean/`:

```sh
lake build differential
lake exe differential ../decompress_g2_vectors.txt --g1 ../decompress_g1_vectors.txt
python3 -I Test/check_g1_controls.py
```

The differential executable exits 0 when every value matches. It exits 1 on a mismatch or an extracted computation returning `fail` or `div`. It exits 2 on invalid arguments or an unreadable, malformed or incomplete file. The Python entry point runs both `check_g1_controls.py` and `check_g2_controls.py`. They require those exit codes and diagnostics on valid small fixtures with permitted whitespace/comments, corrupted kernel/scalar/wrapper values, truncated input and out-of-range references. G2 also checks corruption of an undecided infinity verdict, missing wrapper cases, count mismatch, wrong limb count and trailing text. Building the executable for the first time can take several additional minutes.

From the repository root, fetch the KZG specification vectors and run the crate's Rust checks, including comparison with the c-kzg reference implementation:

```sh
make -C crates/crypto_simd
SILVER_REQUIRE_IFMA=1 cargo test --locked -p silver_crypto_simd --all-features
```

The IFMA requirement applies to BLS and Fr FFT kernel checks on a supported x86_64 host. Serialize top-level Lean commands because each Lake build can run several Lean processes and use substantial memory. Rebuild changed imports before using control or differential results.

### Reproducing the extraction

`lean/extract.sh` reruns Charon and Aeneas on `silver_crypto_simd`, comparing `Extracted/Types.lean`, `Literals.lean` and `Funs.lean`. `AENEAS_DIR` must name an [Aeneas](https://github.com/AeneasVerif/aeneas) checkout matching `lean/lake-manifest.json`. In that checkout, `make setup-charon` builds Charon at `charon-pin`, and `make` builds Aeneas. Charon also needs rustup to install its nightly. The script verifies checkout pins and both binaries' reported commit identities. From `lean/`:

```sh
AENEAS_DIR=/path/to/aeneas ./extract.sh --check
```

Extraction runs the pure-Python setup-literal check and needs no Lean toolchain or compiled proof artifacts. The SHA, decoder, MSM, tower and pairing mutation scripts run separately after `lake build`; use the commands above.

Aeneas records each item's origin in a `Source: '<file>', lines <span>` comment. The comparison ignores the line numbers in these comments and compares everything else exactly, including comment delimiters. A Rust edit that only moves these source locations therefore produces no reported drift. `--check` preserves the generated files. It prints other differences and exits 1, or exits 0 when none exist.

If the generated code has drifted, run `./extract.sh` without `--check`, which replaces `Types.lean`, `Literals.lean`, `Funs.lean` and `controls/ExtractedLiterals.lean`, and follow `lean/README.md`. Rebuild and fix the affected BLS or KZG refinements. Update the models and specification proofs where behaviour changes. Then rerun the controls, Lean differential tests and Rust checks, and update the BLS source table below when its files change. A passing vector test does not replace the drift check, since it covers only the recorded inputs.

The extraction roots include the BLS decoders, typed-point methods, `crate::bls::pairing_product`, `crate::kzg::verify` and `crate::kzg::cell_extender`. They reach both KZG types' public methods and `Default` implementations. They also reach IFMA kernels, `CurveWork`, streaming SHA, portable arithmetic, the portable decoder and MSM, and lane pairing. G1 decoding without IFMA and scalar KZG pairing are opaque operations in `KzgExternals`. G2's `uncompress_in_g2_blst` and signature pairing's `blst_is_one` remain opaque. `prepare-extraction.py` then:

- introduces a section with `RuntimeFeatures`, `KzgExternals`, the G2-only `BlsExternals` and `PairingExternals`; Lean retains a parameter only where a generated definition uses it;
- quotes the eight generated `full` identifiers and disables name-style linting for fixed Rust symbol names;
- supplies structural `Array.make` length witnesses;
- recursively hoists G1 setup rows and pairing-table steps/lanes into the separate `Extracted/Literals.lean` module, preserving each literal's type, order and contents.

Both extraction modes retain raw `Funs.lean` in temporary storage and independently expand the prepared literals against it. Validation runs before comparison or replacement. The script also regenerates `controls/ExtractedLiterals.lean`: `--check` compares it, and default mode updates it.

The separate literal module prevents ordinary function edits from rebuilding the large tables. `controls/ExtractedLiterals.lean` checks equality with the unhoisted extracted literals. Preparation validates required entry points and literal structure. Extraction fixtures accept source-span changes and reject semantic drift, malformed literals and missing or duplicated entries.

All adaptations run before drift comparison. Only numeric source spans are masked. The rest of the generated files is compared exactly. Handwritten external files are preserved by regeneration.

### Project map

| Path under `lean/` | Content |
|---|---|
| `lean-toolchain`, `lakefile.toml`, `lake-manifest.json` | Lean and dependency pins: Lean v4.35.0, Mathlib v4.35.0, upstream EthLib at `98395150` and Aeneas at `nightly-2026.10.30-de16f3c` (`backends/lean`). `lakefile.toml` also sets `autoImplicit` and `relaxedAutoImplicit` to `false`. The manifest records exact resolved revisions; `extract.sh` reads the Aeneas pin from it. |
| `LeanBlsSimd/Constants.lean` | p, r, z, R, the Rust constant tables, and parameter, ψ and chain facts for the specification bridges. |
| `LeanBlsSimd/Spec/` | G1 and G2 Scott equivalence, upstream point-count facts, generator identities, field and group laws, and square roots. Includes KZG encoding and affine-layout bridges. |
| `LeanBlsSimd/Extracted/` | Generated `Types.lean`, `Literals.lean` and `Funs.lean`; regenerate these files. Handwritten external definitions live in `TypesExternal.lean` and `FunsExternal.lean`. |
| `LeanBlsSimd/Model/` | The Rust, transcribed by hand: the proved intermediate step between the generated code and the specification. |
| `LeanBlsSimd/Proofs/` | The model against the specification, including G1's `DecompressG1.lean`, G2's `Kernel.lean` and the G2 wrapper verdict bridge in `UncompressG2.lean`. |
| `LeanBlsSimd/Refines/` | Generated code against the model, function by function. Wrapper APIs: `UncompressG1.lean` and `UncompressG2.lean`. Length mismatches: `WrapperLengths.lean`. G2 kernel headline: `Complete.lean`. |
| `LeanBlsSimd/Kzg/` | KZG specification decomposition, setup certificates, decoder bridge, representation laws, verifier refinements and public statements; `Extender/` contains the cell-extension model, refinements and specification bridge. |
| `LeanBlsSimd/Msm8/` | Generated verifier MSM refinements: GLV splitting, stores, buckets, affine batches, complete sums and output representation. |
| `LeanBlsSimd/PairingProduct/` | Variable-Q pairing steps, lane conversion and packing, arbitrary-length Miller products, owner lifecycle and verdict headlines. The blst route has a separate agreement law. |
| `LeanBlsSimd/Axioms.lean` | The common axiom guard for BLS and KZG. |
| `controls/` | BLS/KZG Lean controls, the common `AxiomLog.lean`, `KzgStrictAxioms.lean`, extraction fixtures in `extraction-check.py`, and the independent `downstream/` package. |
| `Test/Main.lean`, `Test/Differential/` | The differential CLI, shared parser and separate G1/G2 checks; the G1/G2 module docstrings describe the formats. |
| `Test/check_g1_controls.py`, `Test/check_g2_controls.py` | Positive formatting and negative value/parser controls for both differential runners; the G1 entry point runs both groups for CI. |
| `extract.sh` | Regenerates `LeanBlsSimd/Extracted/Types.lean`, `Literals.lean` and `Funs.lean`, or checks them for drift. |

`Refines/Constants.lean` binds the extracted Rust constants to the Lean tables. Their values are checked at their consumers in `Proofs/Fp8.lean`, `Proofs/Fp8Holds.lean`, `Proofs/Limbs.lean`, `Proofs/Pow.lean`, `Proofs/Decode.lean` and `Portable/Fp/Words.lean`.

## BLS proof internals

The proof has two parts. Generated code returns exactly the handwritten model's result. The model agrees with the specification on every lane the kernel decides. G2's Scott completeness uses EthLib's exact twist point count, transported to E′. G1 uses the elementary finite point-count bound described below. Recorded test vectors also compare the generated code and model with the compiled Rust. Those tests check the translation on particular inputs; they are not a proof of the translation itself.

Silver-defined dimension constants carry `@[implicit_reducible]` at their definitions. Imported arithmetic constants receive only file-local attributes. These elaboration attributes add no axioms. Staged kernel certificates check large closed computations before their results enter composed proofs.

### Montgomery multiplication and squaring

`Proofs/EarlyCarry.lean` proves the wrapping carry identity under the inverse-modulus premise. `Proofs/Reduction.lean` equates each generated reduction row with the reference model on limbs above its row index. It transports agreement through all rows and final carry extraction. The row's dead low limb is deliberately outside this equality. `Proofs/Square.lean` equates the triangular square accumulator with the full product accumulator, including wrapping additions. The Fp8 and Fr8 refinements use these identities to reuse the existing arithmetic bounds and public contracts.

### Lazy field arithmetic and point formulas

Fp8 uses the same [range classes as the Fr8 FFT kernel](#ifma-fr-fft-kernel), with modulus `p` and eight radix-52 limbs:

| Class | Integer value | Limbs | Lean predicates |
|---|---|---|---|
| Normalized | In `[0, R)`, where `R = 2^416` | Each in `[0, 2^52)` | `SignedLimbs.Normalized` |
| Reduced | In `[0, 2p)` | Normalized | `Fp8Inv`; `Fp8.Holds` also records the field value |
| `Lazy k m` | In `[0, k*p)` | Signed magnitudes below `m*2^52` | `Fp8.Lazy`; `Fp8.LazyRep` also records the field value |
| Bounded | In `[0, k*p)` | Normalized | `Fp8.BoundRep` records the bound and field value |
| Offset | Exactly `c*p` | Normalized | `Fp8.Offset` |

The shared `SignedLimbs` model defines raw addition, offset subtraction and signed carrying for both fields. Its width-generic normalization theorem preserves values in `[0, 2^(52*n))` when each limb has magnitude below `2^62`. The five- and eight-limb theorems follow as corollaries. `Refines/SignedLimbs.lean` shares the normalization, raw-addition and offset-subtraction refinements across both widths. `Proofs/Fp8Lazy.lean` connects these operations to Montgomery field values and composes their bounds. `Proofs/Fp8Holds.lean` supplies the reduced field representations shared by Fp8 and Fp2 proofs. Conditional subtraction preserves residues when its offset is a multiple of `p`. `Proofs/Fp8Multiple.lean` proves that `multiple_of_p c` returns normalized limbs for `c*p`, for every `c < 2^12`.

`mul_spec_of_product_lt` accepts normalized operands with product below `R*p` and proves a reduced result. The existing multiplication theorems follow as special cases. G1 formulas keep intermediate values below `10p`, with limb magnitudes below `6*2^52` before carrying. Their largest product bound is `8p * 8p`, from squaring the doubled difference in point addition. Offsets of `2p`, `4p` and `8p` keep differences nonnegative; final conditional subtractions restore reduced coordinates. The G1 correctness theorems retain their reduced input and output contracts and their undecided-mask premises.

`Fp2x8.LazyRep` and `Fp2x8.BoundRep` apply the Fp8 classes to each component. `BoundRep.mul` accepts normalized components below `16p`; its Karatsuba sums stay below `32p`. The largest underlying Fp8 product is below `1024p²`, which is below `R*p`. `BoundRep.square` accepts normalized components below `8p` and offsets the component difference by `8p`. Its imaginary component uses `c0 * (2*c1)`, carrying the doubled operand before multiplying. Both lemmas return reduced components; the existing reduced-input `Holds.mul` and `Holds.square` statements follow as corollaries.

G2's double and affine-add formulas use the same componentwise bounds as G1, with reduced coordinates at both boundaries. Their multiplication operands stay below `16p`, and their square operands below `8p`. G1 and G2 retain separate models of Rust's offset structs but share the Fp8 reduction-chain proofs. The G2 formula theorems preserve their exact field triples and undecided-mask equalities.

### G1 Scott criterion

The Scott lemmas use σ(x, y) = (βx, y), with β fixed by the kernel's `BETA_MONT`, and the identity σ²(P) = [−z²]P. Completeness uses EthLib's `G1.exists_nsmul_generator_of_modulus_smul_eq_zero` to express every rational r-torsion point as a generator multiple. EthLib proves this span from the bound `Nat.card E.Point ≤ 2 * p + 1 < r²`. Formula correctness is conditional on a clear undecided bit; the headline theorem does not require proving that subgroup members always avoid exceptional formulas.

### G2 wrapper refinement

The wrapper model uses SIMD availability, a threshold of three inputs per chunk, and padding that repeats the last input. `DecompressG2.decompress_lane` expresses each lane result using that lane's bytes. `UncompressG2.chunk_slice_refines` proves padding accesses stay in bounds and the generated padded chunk equals `chunkAt` exactly.

### G2 kernel proof and completeness

`Spec/G2Group.lean` defines silver's `G2.toPoint` through upstream's map and an additive equivalence induced by `Fp2.toField`. Validity uses `EthLib.Cryptography.Bls.G2.Valid` directly. The same equivalence transports the exact point count to E′. The Scott argument stays on E′ over the quotient tower. `Spec/Membership.lean` owns the field addition formula and its lemmas on arbitrary `Fp2Field` triples.

`decompress_eq_spec` states the model result used by the [G2 kernel claim](#g2-kernel):

```lean
theorem decompress_eq_spec (hC : ScottComplete)
    (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) (l : Fin 8)
    (hu : (decompress inputs).undecided.toNat.testBit l = false) :
    (if (decompress inputs).valid.toNat.testBit l then some (decompress inputs).points[l]
      else none) =
    (match G2.uncompress (toBytes inputs[l]) with
      | .error _ => none
      | .ok P => if G2.inSubgroup P then some (blstLimbs P) else none)
```

The model's agreement with the generated code is therefore proved. Agreement between that generated code and Rust still depends on the extraction and external definitions in the trust list.

The model theorem takes two hypotheses; the headline theorem keeps only the first:

- The undecided bit is clear (`hu` in `decompress_eq_spec`): the kernel decides the lane. `mod.rs` sends undecided lanes to blst. The theorem gives no specification result for those lanes, although unconditional refinement still covers their computed fields. The canonical infinity encoding is one such lane.
- `hC : ScottComplete`: every point P of E′ with [r]P = O satisfies ψ(P) = [z]P. The model theorem retains this parameter; `scott_complete` proves it and supplies it to the headline theorem.

The proof does not show that valid subgroup points always take the SIMD fast path rather than the blst fallback. Wrapper correctness covers fallback lanes through `BlstMatchesSpec`.

The supporting theorems that mention `decompress` refer to the model function and are stated in `lean/LeanBlsSimd/Proofs/Kernel.lean`. Through `decompress_refines`, they also apply to the generated `decompress`, with its result converted by `ofBatch`.

| Theorem | Statement |
|---|---|
| `valid_sound` | A `valid` lane decodes to a point of G2, and `points` holds it. It needs no Scott completeness, and `valid` implies the lane is decided. |
| `valid_complete` | Under `hC`, a decided lane that decodes to a point of G2 is `valid`. |
| `decode_lane` | On a decided lane, `on_curve` is set exactly when `G2.uncompress` succeeds. |
| `psi_generator` | ψ(G) = [z]G for the specification's generator G, in `Spec/Generator.lean`. |

`psi_generator` proves the Scott identity at G without assuming completeness. Its controls reject the opposite sign of z and two wrong ψ constants. `Spec/G2Cardinality.lean` extends this identity to every rational r-torsion point.

`Spec/ScottCardinality.lean` proves that G has exact order r, using EthLib's primality certificate for r. EthLib's `G2SubgroupSpan` proves the exact curve order r · h. Lean's kernel checks coprimality of h and r. `Spec/G2Cardinality.lean` transports that order from EthLib's curve over `Fp2` to E′ over `Fp2Field`. The transport uses `Fp2.toField` on affine coordinates and preserves the point at infinity.

The quotient by G's cyclic subgroup has order h and therefore has no nonzero r-torsion. Every rational r-torsion point is then a multiple of G, so the generator identity gives `scott_complete : ScottComplete`. The conditional cardinality and cyclicity APIs remain available. `Spec/Fp2Tower.lean` supplies the field cardinality and characteristic facts used by the quotient tower and pairing proofs. These field facts do not import the G2 order certificates.

### Vector evidence

Rerun the Lean check when its code, toolchain, dependencies or vector file changes.

`decompress_g1_vectors.txt` contains 47 batches (376 lanes), both masks and twelve limbs per kernel point, plus the scalar blst verdict on every lane. Cases cover both signs, generator multiples, all five small cofactor prime orders, non-members and non-residues. They include x near p, every flag combination and malformed infinity.

The same file records 24 wrapper cases in three families at lengths 0, 1, 7, 8, 9, 15, 16 and 17.

The G1 checks are:

- `g1::replay_vectors` runs the G1 replay check.
- `g1::recorded_matches_blst` checks the G1 recording against blst.
- `lake exe differential ../decompress_g2_vectors.txt --g1 ../decompress_g1_vectors.txt` compares the model, extraction and recorded blst verdicts. The G1 wrapper uses the proved portable decoder for IFMA tails and undecided lanes, and recorded blst observations without IFMA. These finite comparisons supplement the portable decoder proof and check samples of the external law.

The pinned specification and blst 0.3.16 agree on canonical compressed infinity. Both accept `0xc0` followed by 47 zero bytes and reject other infinity encodings. `validateKzgG1` explicitly allows this encoding. `G1.uncompress` returns `G1.zero`. blst's `POINTonE1_Uncompress_Z` zeroes the affine output for it. `blst_p1_affine_in_g1` accepts it. The kernel marks compressed infinity lanes undecided. The public G1 wrapper handles them through its portable decoder on IFMA and blst otherwise. The Lean infinity lemmas prove the specification verdict and kernel fallback behavior. The vector file separately records blst agreement.

`decompress_g2_vectors.txt` holds 105 eight-encoding batches, totaling 840 lanes. It records all three masks, every returned point and a scalar blst verdict on each lane. Seeded cases use `src/bls/tests/g2_cases.rs`, shared with the crate's tests. Edge cases cover flags, infinity encodings, coordinates near p in every word, nonsquare x-values, non-members and small-order points. Both early returns are exercised, taken and not taken.

The same file records 39 G2 wrapper cases across member, mixed and rejected families. Their lengths are 0, 1, 2, 3, 4, 7, 8, 9, 10, 11, 15, 16 and 17. Mixed cases include canonical infinity, malformed infinity and rejected encodings. These lengths exercise the threshold, full chunks and tails on both sides of the threshold.

The G2 checks are:

- `replay_vectors`, in `vectors.rs`, runs the current kernel and public wrapper on the recorded inputs and fails if any output differs. The wrapper starts with nonzero output sentinels. It runs with the crate's other tests. On x86_64 it skips when the `simd` feature or AVX-512F/IFMA support is unavailable; setting `SILVER_REQUIRE_IFMA` to any value makes that a failure. On other architectures this test target contains no tests, even with that variable set.
- `recorded_matches_blst`, also in `vectors.rs`, checks the recorded outputs against blst. It checks recorded scalar verdicts against `uncompress_in_g2_blst` and wrapper outputs against those verdicts. It compares acceptance and accepted kernel limbs on all 716 decided lanes. It uses recorded outputs instead of running the kernel, so it needs no IFMA and never skips on x86_64.
- `lake exe differential`, in `lean/Test/Main.lean`, runs the model and generated kernel on the same inputs through Lean's compiler. It compares `G2Spec.verdict` with recorded blst verdicts on every input, including undecided and infinity lanes. It checks both SIMD settings of the model and generated wrapper, using recorded scalar externals and nonzero output sentinels. It fails if any compared value differs. These finite checks do not prove `BlstMatchesSpec`. The runner reports kernel, spec/blst and wrapper times separately; they are test-run timings, not performance benchmarks.

When all three checks pass and `replay_vectors` has run rather than skipped, the Rust, model and generated code agree on every recorded batch. The specification agrees with blst on all recorded inputs. Canonical infinity is `0xc0` followed by 95 zero bytes; its verdict is `some` of 24 zero limbs. The wrapper checks exercise the recorded cases, while the Lean theorem covers all lengths and inputs under its stated premise.

`replay_vectors` detects changes to the kernel's outputs on these inputs, including `points` on lanes the caller never reads. Unlike the source hashes below, it ignores changes to comments and formatting. The batches do not exercise every possible discrepancy. Scott's two coordinate comparisons always agree on them, so changing only one can go undetected.

Format details live in `lean/Test/Differential/G1.lean`; G2's format lives in `G2.lean`.

`g1::write_vectors` is the ignored G1 generator.

When `replay_vectors` fails, `lean/README.md` explains what to do. To regenerate the files, run this from the silver repository root on an x86_64 host with AVX-512F and AVX-512 IFMA:

```sh
cargo test -p silver_crypto_simd --profile release-with-debug --test proof_vectors -- --ignored write_vectors
```

G2's `write_vectors` checks the mask expectations attached to each edge batch before writing the file. Some expectations constrain only selected lanes or masks. Both generators check acceptance and accepted points against blst on every decided lane. Any failed check leaves the file untouched.

### BLS proof controls

Paths below are relative to `lean/controls/`. The common reproduction commands run these files alongside the KZG controls.

| File | Shows |
|---|---|
| `Guard.lean`, `GuardPartialPermission.lean`, `GuardImported.lean` | The guard rejects native evaluation, local and imported constructor cycles, and partial permission for a theorem's two axioms. |
| `AxiomInventory.lean`, `AxiomInventoryExtra.lean`, `AxiomInventoryMissing.lean`, `AxiomInventoryDropped.lean` | The production axiom-name set passes. An unused extra axiom fails; a Lean-only import rejects all three missing Aeneas names. Reimporting the dropped `PanicInfo` axiom fails. |
| `G1.lean` | Concrete G1 constants, routing flags, signs and limb order; skipping canonicality makes the kernel accept a noncanonical encoding of 2G. Also covers full chunks, scalar tails, empty output and arbitrary fallback. |
| `downstream/` | Transports both groups' list results across independently extracted structs and checks a generated-spelling caller using downstream externals. Guards root-name collisions and proof axioms. |
| `G2Wrapper.lean` | Wrong SIMD routing, thresholds, ignoring undecided lanes and dropping accepted kernel results change observable verdicts (the accepted-result mutation is a compiled `#eval`). Tail controls distinguish scalar and kernel routing after a full chunk; reading the chunk's first input on fallback changes the verdict. Rejecting infinity, accepting malformed infinity or returning wrong affine limbs violates `BlstMatchesSpec`; unequal lengths fail. These controls do not claim to observe padding contents. |
| `G2Consumer.lean` | Applies G2 list, model and length-mismatch corollaries from a separate module. A specification-backed external satisfies the universal premise at both SIMD settings. |
| `G1Consumer.lean` | A downstream module applies the general G1 theorem under its scoped decoder law. It applies the IFMA result with no blst agreement premise. |
| `Statements.lean` | Changed constants and formulas break their proof scripts, including G1's Scott-membership proof when the model drops the y negation. |
| `Limbs.lean`, `Fp8.lean`, `Decompress.lean` | A mutated constant, formula, carry or mask breaks the proof that uses it. `Limbs.lean` also shows that the early-carry model expression depends on its shift. |
| `G2Group.lean` | An off-curve point shows that the subgroup implications require validity. |
| `EarlyCarry.lean` | Both modulus constants satisfy the carry identity; omitting or decreasing MASK52 and replacing the wrapping sum by a natural-number sum give concrete counterexamples. |
| `Square.lean` | The triangular square accumulator equals the full product; omitting cross-term doubling fails on an input with two nonzero limbs. |
| `Fp8Lazy.lean` | Missing conditional subtraction violates the reduced bound; an insufficient offset makes a difference negative; a tighter lazy bound fails. Normalized operands alone do not guarantee a reduced product. |
| `Fp2Lazy.lean` | Karatsuba sums need carrying; a smaller square offset makes a valid lazy difference negative. Omitting the imaginary-component doubling violates the square contract. |
| `G2Lazy.lean` | Dropping the final conditional subtraction leaves nonreduced components. Replacing the double formula's `8p` offset with `4p` makes a valid intermediate difference negative. |
| `Reduction.lean` | Both widths retain the stale dead limb; dropping the inverse premise can change a surviving limb. The valid inverse case agrees above the row index. |
| `Generator.lean` | −z, or a wrong ψ constant, breaks `psi_generator`. |
| `ScottCardinality.lean` | The generator's order is not r². A group of order four shows why the cardinality argument needs both its exact count and coprimality premises. |
| `G2Cardinality.lean` | Checks the transported exact order, Scott soundness and completeness, the conditional cardinality API and their standard axiom lists. |
| `Kernel.lean` | Checks the input premises and conclusions on concrete batches, including the generator's batch. These examples need no Scott completeness assumption, but do not prove completeness for arbitrary inputs. |
| `Refines.lean` | Mutated generated functions fail their refinement proofs, including G1's chunk fallback reading lane zero instead of the current lane. Concrete refutations cover five complete G2 refinements and the required loop steps for `times_minus_z` and G1's fallback. |
| `AxiomLog.lean` | Prints Lean's recorded axiom lists for public library theorems and checked generated definitions. |

### Extracted BLS source

`lean/LeanBlsSimd/Extracted/Types.lean`, `Literals.lean` and `Funs.lean` contain items generated from the following Rust files. These content hashes inventory selected BLS sources, including shared arithmetic and the verifier MSM module. `extract.sh --check` verifies their correspondence with the generated files.

| File | sha256 | git blob |
|---|---|---|
| `mod.rs` | `20f873dd603b79c7ebfaed7405c59b8198e1161ec1ee70197e061437a06baa76` | `8204f14684ac97330da7adbe7e416f9b49b67996` |
| `constants.rs` | `271dee35efa3f287af9f7f595f40f3a4c33eccf2ce5e6fd78ecf7c0feb09ee15` | `57e42041a030367d6feafacaeb4cb9fe3a01c791` |
| `fp8.rs` | `a9e98e79112affc6b40ddf6a46e1364cc8a6834eecceac8c147805cec8cbd60e` | `2ae5aaec3ad3d7b25d3c70b762422e4ad81f1edf` |
| `fp2x8.rs` | `ca765c2445eb8e27e63e3715b582ea7048c3edac48f5d59a2656559fd156a38a` | `cd57da198083218c44eb0b544b970dd9b0828ff9` |
| `g1x8.rs` | `d9a036baa23fbf280ca404dec08048ba62738a35876cf91d5cc02bb9b355cbfd` | `6a540978f71d1a5201c2a056f5f7e5361929fe7d` |
| `g2x8.rs` | `3e5da4797933264da07aa002060cb02d9b0caf794013c02a2a1984b174e9294b` | `9bbffcc30319f2c024adfa74748ad57e4236b437` |
| `decompress.rs` | `682defa9c6b4fef72260d07003ec8007f4bf06c00cc62aa5fe011400914bde2c` | `7e95e5715db47f8b3596b6fb29293d268c581e79` |
| `decompress_g2.rs` | `90191fefc1a2098886b5573306e338a82caf3f2711cbcced9db2ed673a8c21ed` | `197c67ee347254fe211a261e6909f0105c9e9307` |
| `msm8/buckets.rs` | `0ed726ff2bb8cefd20c779dcd189e9d6e5c3a4d48525ea3575d5c451e4168aa3` | `4dfe60b4ef0b091052f6e7c69bb03626ae083c5a` |
| `glv.rs` | `bf298f838003c087769cb56f78551c6c44be19e61eb7dc0f9829a15403f6d74b` | `b928b5ac231282c0f01a501374503e7c41798c7b` |
| `msm8/mod.rs` | `699d4908ebac51a2a2907d62cb18ab54347e97f609a56f6796c38647bc24a728` | `c326c5bcee0b2bcfdf31b78c4957217829fd54b9` |
| `msm8/pairs.rs` | `077b573f161a722c9093a83faee58752c0561949b03426efdd1fac365e314efe` | `7285f65839a8f9a75b462ee63f859d22ce989799` |
| `msm8/store.rs` | `ff222942cf6f62cec177664dcc31b6704fb32b787a47b15a528fa376f68e3f07` | `7578f4b062dc207371273f4c99a299e1be25f12f` |

The MSM uses `msm8/`, shared `fp8.rs` inversion and `g1x8.rs` complete point operations.

G1 coverage includes `uncompress_in_g1`, `decompress_g1_chunk`, the decoder, group operations and shared arithmetic. Portable G1 decoding for IFMA tails and undecided lanes has a proved generated-code contract. The non-IFMA route uses the scoped blst decoder law. CPU observations are external inputs. G2 coverage includes `uncompress_in_g2`, `decompress_g2_chunk`, the decoder, group operations and shared arithmetic. The G2 wrapper refinement proves the chunk routing, padding bounds, fallback calls and output writes. The consolidated trust list describes the correspondence to `coreVerify`. The extraction also includes blst 0.3.16's field and affine structures from `src/bindings.rs`.

To check for changes since the proof, run this from `crates/crypto_simd/src/bls`:

```sh
sha256sum -c <<'EOF'
20f873dd603b79c7ebfaed7405c59b8198e1161ec1ee70197e061437a06baa76  mod.rs
271dee35efa3f287af9f7f595f40f3a4c33eccf2ce5e6fd78ecf7c0feb09ee15  constants.rs
a9e98e79112affc6b40ddf6a46e1364cc8a6834eecceac8c147805cec8cbd60e  fp8.rs
ca765c2445eb8e27e63e3715b582ea7048c3edac48f5d59a2656559fd156a38a  fp2x8.rs
d9a036baa23fbf280ca404dec08048ba62738a35876cf91d5cc02bb9b355cbfd  g1x8.rs
3e5da4797933264da07aa002060cb02d9b0caf794013c02a2a1984b174e9294b  g2x8.rs
682defa9c6b4fef72260d07003ec8007f4bf06c00cc62aa5fe011400914bde2c  decompress.rs
90191fefc1a2098886b5573306e338a82caf3f2711cbcced9db2ed673a8c21ed  decompress_g2.rs
0ed726ff2bb8cefd20c779dcd189e9d6e5c3a4d48525ea3575d5c451e4168aa3  msm8/buckets.rs
bf298f838003c087769cb56f78551c6c44be19e61eb7dc0f9829a15403f6d74b  glv.rs
699d4908ebac51a2a2907d62cb18ab54347e97f609a56f6796c38647bc24a728  msm8/mod.rs
077b573f161a722c9093a83faee58752c0561949b03426efdd1fac365e314efe  msm8/pairs.rs
ff222942cf6f62cec177664dcc31b6704fb32b787a47b15a528fa376f68e3f07  msm8/store.rs
EOF
```

If a file fails, find its proved version with `git log --all --find-object=<blob>` and diff the two, then check the generated code for drift.

## KZG proof internals

### Verifier proof structure

| Selected files under `lean/LeanBlsSimd/Kzg/` | Role |
|---|---|
| `Representation.lean` | Byte, Montgomery-limb, affine and Jacobian interpretations |
| `ScalarContracts.lean`, `Fr/` | Proved scalar arithmetic and byte laws, with shared word lemmas in `Refines/Word64.lean` |
| `ShaContracts.lean`, `PortableFp.lean`, `PortableMsmContract.lean`, `PairingContract.lean` | Proved generated-component contracts |
| `PairingCorrect.lean` | Lane pairing and the proved `PairingCorrect` statement; `BlstPairing.lean` supplies the scalar boundary |
| `CurveWorkState.lean`, `PairingTable.lean`, `PairingTableBounds.lean`, `CurveWorkConstruct.lean` | Route preservation, unrestricted curve scratch, lane-table bounds and workspace construction |
| `Model.lean` | Spec decomposition, column-aggregated IFFT and intermediate computations |
| `IOLawful.lean` | Lawful `EST` and IO instances for monadic specification rewrites |
| `SpecBridge.lean` | Full-result correspondence between the pure model and upstream |
| `SetupArithmetic.lean`, `SetupPoints.lean`, `SetupValidity.lean` | Staged kernel certificates for embedded decoding, subgroup membership and affine validity |
| `Setup.lean` | Embedded-byte connection and persistent-state invariant |
| `PolynomialModel.lean`, `PolynomialArithmetic.lean` | Cell interpolants and inverse FFT; coefficient-array injectivity, addition and constants as Mathlib polynomials |
| `CosetPolynomial.lean`, `ColumnPolynomial.lean`, `InterpolationIdentity.lean` | Coset IFFT correctness and weighted column interpolation |
| `ModelSpec.lean` | Input invariants and full-result spec equivalence |
| `Statements.lean` | Model/spec equivalence, interpolation, construction, refinement and headline theorems |
| `Refines.lean` | Supporting statements for decoding, challenge, roots, IFFT and pairing inputs |
| `Refines/` | Proofs for the extracted functions and shared loop lemmas |
| `InterpolationKernel/` | Canonical cell checks, weighted columns, the shared 64-point DIT, coefficient stores and kernel construction |
| `Lincomb.lean` | Actual `verify.CurveWork.sum`, ordinary scalar conversion, proved lane and portable MSM |
| `Routes.lean` | Preservation of the interpolation option, curve-work route and stored table through successful calls |
| `Decoder.lean` | Direct composition with the shared BLS decoder proofs |

`column_ifft_eq_interpolation` states T1: the spec's per-cell interpolation step, with the shifts it computes (`indices.map Model.cosetShift`), equals the column IFFT (`Model.columnRli`). It holds for aligned arrays, 64 field elements per cell and indices below 128. These are intermediate invariants established by the front half, not new assumptions on untrusted inputs. `ModelSpec.verifyPure_spec_eq_column` replaces the specification interpolation step for any fixed setup, preserving the complete `Except` result. `RliInputs` includes equal powers and index lengths. The front half establishes these aligned batches for refinement. The proofs establish index bounds and compression/decompression round trips explicitly. Lean's logical `get!` and panic fallback values alone cannot certify that execution avoids those branches.

The streaming challenge proofs accumulate the exact upstream transcript in both SHA paths, then use the proved reducing scalar decode. The inverse FFT proof covers the generated recursive transform and scaling. The aggregation, bit-reversed column copy and shift-add loops are proved separately. `InterpolationModel.lean` proves that their pure composition equals `columnRli`, including skipped zero columns. The interpolation commitment and pairing proofs compose these loops with the proved portable field/MSM and lane pairing contracts. They also use the scoped scalar blst pairing law. `ModelPairing.lean` proves the corresponding pure-model computation, including successful compression round trips and empty linear combinations. `glue_refinement` combines every generated verifier branch with that model under the state invariant and slice-size premises. It preserves the invariant for subsequent calls. `InterpolationIdentity.lean` interprets the specification's coset interpolation directly as Mathlib polynomials. Upstream supplies the IFFT evaluation law for 64 values and a nonzero shift, and the distinct coset nodes of valid cells. `cellIfft_interpolant` connects the total IFFT transform to Lagrange interpolation; interpolation linearity regroups the weighted cells by column. Scalar weighting uses upstream's product evaluation law and Lagrange uniqueness on the 64 cell nodes. Both arrays retain size 64, so polynomial injectivity recovers exact array equality, including trailing zero coefficients. `ModelSpec.lean` derives the intermediate shape contract from successful decoding. It replaces the interpolation step while preserving the full `Except` result and arbitrary setup-loader actions. The embedded-setup proof uses `column_ifft_eq_interpolation` and `ModelSpec.verifyPure_spec_eq_column`.

Upstream's explicit coset shifts enter `Model.RliStep`. `ModelSpec.mapM_shiftOf` identifies the computed shifts, and `specRli_polynomial` interprets the resulting per-cell interpolation. `cellIfft` returns an array for every input length; upstream `interpolateCosetEvals` checks the length and returns `Except`. Their successful results agree for 64 values. `ModelPairing.implPure_eq` uses decoded `setup.g1Monomial` points for its interpolation commitment. Validated setup decoding supplies their equality with Silver's model points.

`SpecBridge.lean` proves `verifyWith_pure` for every setup, RLI step and input, preserving the complete `Except` result. `g1Lincomb_eq` connects the pure linear combination to upstream; `upstream_eq_verifyWith` composes the front and implementation decompositions used by the literal-upstream corollaries. `IOLawful.lean` proves `LawfulMonad (EST ε σ)` and derives the IO instance needed by these rewrites.

### SHA-256 and challenge proof

`Sha256/Correct.lean` constructs `Sha256.sha_correct : Kzg.ShaCorrect` for the actual portable and SHA-extension constructors, updates and finishes. Challenge refinements use this theorem and the proved digest reduction internally; they take no hash contract premise.

Both implementations use one `Streaming.Represents` invariant. State words equal the specification compression fold over complete blocks. The first `pending_len < 64` bytes form the remaining suffix; stored length is the absorbed byte count modulo 2^64. `Streaming.update_append` and `finish_eq_hash` are proved once. `Generated.lean` factors schedules definitionally equal to both generated update/finish bodies. Their shared refinements cover filling a pending block, direct block folds, remainder copies, one- or two-block padding and big-endian output. `Spec.hash_eq` proves equality with `EthLib.Cryptography.Hash.sha256` for every message length. It uses wrapped-length semantics directly, without upstream's bounded `hash_eq_spec` or `pad_eq_spec` lemmas. `ContractAdapter.lean` derives observational `ShaRep`; its continuation laws cover every state satisfying that relation.

The portable compressor proves byte loading, all 64 schedule words and rounds, feed-forward and the block fold. The extension compressor proves the ABEF/CDGH layout, four-round instruction and schedule-window steps, the generated inner loops and the block fold. The SHA/SSE models and three hand-replaced pointer routines belong to the documented extraction trust boundary.

### Extender proof structure

`Extender/Model.lean` decodes the blob and applies a 4096-point inverse FFT after input bit reversal. It multiplies coefficients by the first 4096 powers of the 8192nd root, then applies a forward FFT. It copies the original 64 cells and serializes the bit-reversed extension into the remaining 64 cells.

`SpecMath.lean` relates this transform to polynomial evaluation on both halves of the specification's domain. `Spec.lean` uses upstream `computeCells_ok_spec` to equate the complete `computeCells` action with the model, retaining errors; `SpecBytes.lean` proves serialization sizes and byte indexing. `Acceptance.lean` connects successful decoding to canonical big-endian field elements.

`Primitives.lean` proves construction from the shared roots refinement. `Decode.lean` proves decoding and early rejection. `Scale.lean` proves coefficient shifting. `WriteStep.lean`, `WriteBytes.lean` and `Write.lean` prove every output byte and the first-half copy. `Refines.lean` composes the generated operations and preserves `Basic.lean`'s invariant. `Statements.lean` supplies the public results. The roots, scalar FFT and byte bridges use the proved scalar refinements without contract premises. Generated scalar zero, one, roots and inverse-size constants have independent kernel certificates. `Refines/InverseRoots.lean` shares the table-shape proof across 64, 4096 and 8192 entries and derives inverse entries from the root order. `SetupLiterals.lean` certifies the two production G2 coordinate literals against `SetupPoints`. It binds those certificates to the extracted definitions. Run `python3 controls/setup-literals-check.py` from `proof/lean` to compare all 48 limbs with `src/kzg/setup.rs`. The checker also rejects a changed limb in each literal.

#### IFMA Fr FFT kernel

`Kernel/Basic.lean` relates each vector's eight lanes to field elements. Each lane's integer value reads its five limbs as signed 64-bit integers. The range classes match `fr8.rs`:

| Class | Integer value | Limbs |
|---|---|---|
| Normalized | Below `2^260` | Each in `[0, 2^52)` |
| Reduced (`Bounded`) | In `[0, 2r)` | Normalized |
| `Lazy k m` | In `[0, k*r)` | Each has magnitude below `m*2^52` |

`Model/SignedLimbs.lean` and `Proofs/SignedLimbs.lean` provide signed carry and raw arithmetic facts. `normalise` preserves the integer value when its limbs have magnitude below `2^62` and its value lies below `2^260`. `Refines/Fr8.lean` equates uncarried products with `Fr8.mulRaw`, using the [shared early-carry reduction proof](#montgomery-multiplication-and-squaring). `Reduction.rows_agree` transfers the surviving limbs to the reference accumulator. `Refines/Fr8Interleaving.lean` equates each combined row with independent reduction and product rows, including their wrapping additions. `Fr8.reduce_while_multiplying_eq` composes the rows into exactly `(reduce t, product a b)`. `FrModel.Lane.mulAcc_bound` bounds the combined product/reduction accumulator limbs below `2^57` for arbitrary inputs. `FrModel.Lane.mulRaw_bound` transfers this bound to the output limbs. `FrModel.Fr8.mulRaw_spec` also bounds each lane's value below `2r`, assuming normalized operands with `a*b < r*2^260`.

Multiplication constants carry `R = 2^260` and have canonical representatives below `r`. `MultiplierRep` records both properties. `FftInvariant` requires this representation for all wide and short twiddles; `StateInvariant` also requires it for shift multipliers. The constructors establish these invariants through `load_multiplier_refinement`, which proves canonicality from the exact modulo-`r` packing equation, without an additional external premise.

Canonical table multipliers permit multiplication of any normalized data operand within the product bound `a*b < r*2^260`. A noncanonical representative of the same field element need not satisfy that bound. `ExtenderKernelLazy.lean` checks a unit-multiplier counterexample whose raw product exceeds `2r`.

`Kernel/Lazy.lean` connects signed ranges to field representations. `Fr8Lazy.lean` proves normalization and raw operations; `Fr8Mul.lean` proves bounded products. `Fr8Offset.lean` constructs multiples of `r`, `Fr8Reduced.lean` reduces normalized values, and `Fr8AddSub.lean` composes reduced arithmetic. `Fr8Arithmetic.lean` proves canonicalization.

`Fr8ByteLoad.lean` proves the four 64-byte loads used by `U256x8`. `Fr8Swap.lean` proves the shift/mask/add byte swap, and `Fr8Endian.lean` connects it to big-endian conversion. `Fr8Words.lean` proves both rounds of block permutation and the conversion between four 64-bit words and five 52-bit limbs. `Fr8WordStore.lean` supplies the byte-write and frame lemmas. `Fr8BytesDecode.lean` composes these refinements to recover every raw 256-bit input, including rejected values. `Fr8BytesEncode.lean` composes canonicalization and the inverse conversion to prove exact big-endian output bytes while preserving the surrounding output slice.

`Refines/Transpose.lean` proves the shared 8×8 shuffle from its generated intrinsic calls. `Kernel/Fr8Transpose.lean` and `Kernel/Fr8.lean` lift it to all five limbs; `FftOperations.lean` preserves the field representation of each lane. `FftShort.lean` proves stages 1, 2 and 4 on transposed blocks, including the skipped product when the twiddle is 1. `FftShortPipeline.lean` equates the three generated short stages with the per-butterfly loops in `FftShortModel.lean`. `FftShortSteps.lean` supplies loop equations; `FftShortOne.lean` handles the stage without pending products. `FftBlocks.lean` composes the two transposes, short stages and block stores. `Kernel/FftTableBuild.lean` and `FftTables.lean` prove the seven splat twiddles and the strided wide table.

DIT starts with reduced data. Its short stages produce `Lazy 4 3`, `Lazy 8 36`, then `Lazy 16 73`. Each wide stage increases the two bounds by 2 and 33 respectively. For `w = log2(n)-3` wide stages, the result is `Lazy (16+2*w) (73+33*w)`, at most `Lazy 34 370`. The normalization proof uses `k ≤ 35`, the proved inequality `35*r < 2^260`, and limbs with magnitude below `2^62`. Its bound `m ≤ 1024` ensures the limb premise; `Lazy 34 370` meets both bounds. The shift product produces `Lazy 2 32`, the DIF input class. DIF preserves this class until its final short stage, whose outputs are reduced. The byte encoding contract requires reduced inputs.

`FftPairIndex.lean` proves the butterfly index formula and the partition into disjoint pairs. `FftWidePipeline.lean` records completed pairs and the pending product. `FftWideOperands.lean` proves operand reads and output stores; `FftWideRun.lean` proves the generated pipeline preserves this state. `FftWidePair.lean` supplies the per-butterfly arithmetic bounds, and `FftWide.lean` applies them to every output.

`Fft.lean` composes the block pass and wide butterflies. `FftMath.lean` proves the iterative DIT and DIF transforms equal the specification with bit reversal on their input and output respectively. Its induction covers every power-of-two size, including 1; the generated kernel contracts cover sizes 64 through 4096. `RootsValid` uses the specification's primitive-root predicate and powers directly.

`Kernel/Construct.lean` initializes the two FFT tables, shift multipliers and 512 data vectors. `Decode.lean`, `Shift.lean` and `Encode.lean` prove each generated loop, and `Refines.lean` composes them. Rejected decoding retains the raw 256-bit integers, which may exceed the arithmetic bound. The state invariant therefore constrains the data length and immutable tables; the next decode overwrites every data vector before arithmetic. Successful decoding establishes the stronger data representation. Output writes preserve the first 64 cells and serialize the extension into cells 64 through 127.

The scalar and kernel route lemmas preserve the outer extender invariant. The kernel route also preserves all tables, and the scalar route preserves `kernel = none`. Their case split proves the public theorem for construction and repeated calls.

### Verifier interpolation kernel

`InterpolationKernel/Basic.lean` defines the verifier kernel's `StateInvariant`. The inverse FFT satisfies the shared `FftInvariant`, and each shift satisfies `MultiplierRep`. Column, shift and used-flag buffers have fixed lengths. The invariant places no arithmetic condition on stale scratch columns. `Construct.lean` proves these properties from the generated constructor, including canonical shift multipliers for `64⁻¹ * cosetShift(column)⁻ᵏ`. `Roots.lean` establishes `RootsValid` for the 64-point roots and their inverses.

`Check.lean` equates the generated canonical masks with specification decoding for every cell byte string. `CellsRep` connects accepted cells with their 64 field elements. `Fr8Splat.lean` proves the broadcast weight representation, including the factor of 16 converting blst's Montgomery radix to the kernel's. `AddCell.lean` proves weighted accumulation: a column's first raw product is normalized before it is stored, and later additions restore the reduced range. `Aggregate.lean` and `Accumulate.lean` connect the generated used flags and columns to the scalar aggregation model. Clearing the flags makes stale columns irrelevant; each first use overwrites its column with bounded data.

`Column.lean` reuses the extender's `dit_refinement` and lazy range bounds at size 64. It proves the DIT on bit-reversed column data, normalization, multiplication by the column's shift factors and addition into reduced sums. `Store.lean` proves canonical coefficient bytes and their scalar decoding. `Interpolate.lean` composes these operations into exact equality with `Model.columnRli`, preserving the kernel invariant. The interpolation-commitment and pairing proofs compose these results with `verify.CurveWork` for both MSM routes. Scalar bridges use the proved arithmetic and byte refinements; zero, one and inverse-size constants are separately certified.

For source changes, follow the [KZG maintenance guide](lean/README.md#kzg-maintenance). It covers both types, including the verifier's [constructor panic message](lean/README.md#constructor-panic-message).

### Pairing field model

`Spec/Fp6*.lean` and `Spec/Fp12*.lean` give the executable coordinates exact field semantics. `Fp6.toField` and `Fp12.toField` are ring equivalences, with total inverse bridges that include zero. The Fp2 and Fp12 power bridges cover every natural exponent, including `0^0`. The pinned specification has no Fp6 `powNat` operation. Noncube and nonsquare certificates establish both extensions; their cardinalities are `p^6` and `p^12`.

`Cyclotomic.toCubic` embeds this field injectively into a cubic-over-quadratic ring model. `toCubic_fieldDecode` relates that embedding to the six Fp2 coordinates. `Schedule.raw` records the three Fp4 squarings and coefficient order of the Rust cyclotomic formula. `field_cyclotomic_square` proves that formula under the Φ12 relation `g^(p^4-p^2+1) = 1`. The unitary condition alone is insufficient; a checked `−1` counterexample distinguishes it. `field_frobenius` proves the coefficient map with factors `ξ^(j(p−1)/6)`. `field_star` identifies conjugation with the `p^6` power. `field_easy_cyclotomic` proves membership for the nonzero easy-part output; zero maps to zero.

`Refines/FrobeniusConstants.lean` certifies the lane coefficient table at Montgomery radix `2^416`, its canonical values and normalized limbs. `toField_finalExponentiation` in `Spec/FinalExponentiation.lean` identifies the total exponent. The same file proves target-group membership. `Spec/PairingProduct.lean` identifies the pairing fold with a product of factors, including zero and infinity. `Kzg.pairing_correct` proves the lane implementation contract from the lane tower, Miller loop and optimized final exponentiation.

### Lane pairing tower schedules

`LaneTower/Upper.lean` tracks inclusive bounds on signed, nonnegative limb values and their decoded field elements. Zero-valued contributions retain bound zero. `Vectors.lean` and `Pairs.lean` compose generated addition, offset subtraction, normalization, multiplication and lane permutations. The capacity lemmas cover the tower's operands above `1024p`; the existing reduced and lazy arithmetic contracts keep their statements.

`Packing.lean` proves the generated six- and nine-row packing and unpacking, including recovery of all six active lanes after pointwise multiplication. `Products.lean` gives one array-width-generic product-loop proof. `Inputs.lean`, `Recombine.lean` and `Mul.lean:mul_raw` compose the generated multiplication schedule from inputs bounded by `256p` to outputs bounded by `108p`. `Layout.lean:lane_basis` identifies lane `3h+k` with the field basis element `w^(2k+h)`.

`Coordinates.lean:product_value` identifies that coordinate schedule with specification multiplication. `Representation.lean:Rep` requires normalized representatives below `256p` in all eight lanes; `value` reads the six active lanes. The multiplication refinement preserves this representation.

`Basic.lean`, `Square.lean` and `LineCoordinates.lean` refine generated one, conjugation, square and sparse line multiplication. Square and line multiplication produce normalized outputs bounded by `112p` and `120p`. `Frobenius.lean` proves the actual coefficient-loading loop, consumes the decoded lane-table certificate and refines p-th powering. `CyclotomicSum.lean` proves the generated cyclotomic recombination and its `572p` bound. `Cyclotomic.lean` composes the quadratic products and both final conditional subtractions. `CyclotomicCoordinates.lean` equates the result with `Schedule.raw` for every coefficient tuple. It proves square agreement for zero and values satisfying the Φ12 relation.

`InversePower.lean` proves bounded-input inversion without adding a reduction absent from the generated schedule. `InverseStages.lean`, `InverseNorm.lean` and `InverseCoordinates.lean` connect the adjugate, determinant and total inverse, including zero, with a normalized output bound of `108p`. `Identity.lean` proves the normalization-by-one and equality-mask schedule, then identifies its six active bits with the specification identity test.

### Fixed pairing lines and Miller loops

`Pairing/FixedTable.lean` checks all 136 fixed lines against the live generated table. Its division-free certificates cover the running points, slopes, nonzero denominators, curve equations and nonzero normalizers. `FixedTableMeaning.lean:entry_decodes` identifies every decoded Fp2 coefficient; `step_correct` gives its affine line equation. `controls/pairing-table-witnesses.py` regenerates the numeric witnesses from the repository's public table generator. The Lean kernel checks them independently.

`Untwist.lean`, `FixedLine.lean` and `EmbeddedSteps.lean` connect those certificates to the specification's actual line and point operations. `LineScaling.lean` proves that the discarded factor `c*w^(-3)` has period dividing `p^4-1`, so final exponentiation removes it. `MillerSpec.lean` composes all 68 lines with the specification's bit schedule. These final-power equalities include zero line and accumulator values.

`ProjectiveLine.lean` relates the generated G1 factors `[Z³, XZ, Y]` to affine evaluation through a nonzero subfield scale. `SetupEmbedding.lean` identifies the actual G2 setup points with the certified walks. `MillerFactors.lean` and `CombinedMiller.lean` prove the simultaneous two-pair fold's final-power agreement with the product of specification factors, including G1 infinity skips and negative-z conjugation.

`MillerSchedule.lean` certifies the bit-to-row mapping and counter increments. `MillerLoop.lean` composes the countdown schedule, including the omitted first square. `Spec/Line.lean` defines the shared line value under the stable name `Portable.Fp12.line`. `Pairing/LineFactors.lean` defines its factor interpretation.

`LaneTable.lean` connects loaded rows to decoded coefficients at radix `2^416`. `LaneLine.lean` and `LaneLines.lean` prove the permutations and presence-controlled sparse multiplications. `LaneFactors.lean` proves factor preparation and field-zero presence detection, including normalized `z=p`. `LaneMiller*.lean` composes the loop with conjugation. `LaneLines.PointsRep` uses `Fp8.Holds` for all eight coordinate lanes. `Kzg/PairingCorrect.lean` bridges it to `LanesPairRep`.

### Optimized final exponentiation

`Pairing/FinalModel.lean` records the common generated hard-part schedule. A shared schedule-map lemma gives its field exponent, and a kernel certificate identifies that exponent with three times the specification exponent modulo `p^12-1`. `FinalVerdict.lean` proves that the optimized result is the cube of the specification result, including zero. The specification's nonzero result has r-torsion; `gcd(3,r)=1` therefore gives equal identity verdicts. Zero is rejected by both.

`FinalExponent.Good`, defined in `FinalModel.lean`, means the field value is zero or its Φ12 power is one. `FinalInvariant.lean` proves closure. The easy part supplies this invariant for every input, so the optimized-square premises are discharged internally. `ExponentLoop.lean` proves the countdown schedule. `LaneExponent.lean` connects the generated loop and negative-parameter conjugation.

`FinalRun.lean` composes the final chain through `Operations.Refines`, constructed from proved lane operations. `FinalExponent.Lanes.final_verdict` applies to every `LaneTower.Rep` input, with no nonzero or cyclotomic input premise. `final_cube_refines` describes its cube-valued output. Its identity verdict equals the specification verdict.


### Pairing integration

`Pairing/Verdict.lean` turns `FinalEq` into verdict equality and expands the specification's two-pair fold through `toField_pairingFold`. `combined_verdict` unfolds `setupPoint` to `[s^64]G2` and `−G2`.

`Kzg/PairingCorrect.lean` composes the generated lane Miller loop, final exponentiation and identity test. The scalar sum adapter is proved in `Kzg/ScalarPairingInputs.lean`, using portable G1 add and negation. `Kzg/BlstPairing.lean` applies the scoped external law to those sums and the certified extracted G2 literals. Both adapters preserve the pairing verdict across equivalent Jacobian representatives.

### Portable MSM components

`Portable/Msm/Buckets.lean` proves that portable bucket fill has the same generated schedule as the lane implementation after converting its five storage fields. `FillReady.lean` reuses the signed-digit, packing, weighted-sum and live-reference theorems. Its chunk bounds use the generated `CHUNK = 4096` constant.

`Store.Holds` describes canonical coordinates at an initialized slot without constraining reserved scratch. The store refinements prove signed references, writes and their frame property, allocation and reset. `BatchReject.lean` proves the generated equal-x branch returns false before inversion and preserves the store, including the first-job case for arbitrary scratch. `BatchFinish.lean` proves the affine finish formula and reuses the shared nonsingular addition theorem.

`BatchPrepare.lean` and `BatchUnwind.lean` refine each generated step using the shared four-chain product invariant and the proved portable batch inversion. The reverse step recovers each inverse and updates its chain accumulator. `BatchPrepareLoop.lean` composes preparation up to any nonzero prefix, proves later equal-x rejection through scratch resizing, and connects complete preparation to the generated reverse loop.

`BatchExecute.lean` composes the reverse loop under `ExecutionState` and `ReverseIndependent`, permitting a job to overwrite its own input while preserving earlier jobs. `BatchRun.lean` proves `Batch.run_cases`, deriving both rejection and execution for arbitrary scratch, without a successful-batch premise. `Queue.lean` refines each portable queue step, bucket compaction and complete queue round, reusing `QueueRefines` for the packing, allocation and reduction models. A job may reuse its first input slot without spare capacity; odd carries remain live. `PointRep.lean`, `BatchGroup.lean` and `BatchJobs.lean` connect initialized slots and signed references to the affine group. A successful batch installs every queued sum and frames other slots. `RoundLayout.lean` and `PairRounds.lean` prove termination and both outcomes of repeated rounds. Successful rounds preserve bucket sums; rejection preserves the original points needed by refill and returns a nonempty rejected batch.

`Input.lean` proves clearing and finite-input filtering. `Split.lean` reuses the shared GLV loop invariant and group decomposition. `Push.lean`, `PushLoop.lean` and `Prepare.lean` initialize the signed original and endomorphism points from arbitrary scratch and preserve earlier slots. `Initialise.lean` ties those points and the filled buckets to the original input contribution, with capacity and reference bounds discharged for `CHUNK = 4096`.

`Group.lean`, `Join.lean`, `Window.lean` and `Sum.lean` prove complete mixed additions over each packed bucket, weighted window sums, doubling and the outer Horner fold. These proofs share the existing weighted-step and Horner identities and the signed-reference/group-sum bridge with MSM8.

`Finish.lean` composes both round outcomes, refilling rejected rounds from preserved scalar halves and original points before complete summation. `FiniteCore.lean` and `Chunk.lean` include infinity filtering and the empty case. `Refines.lean` proves the unbounded outer chunk fold and constructs the unchanged `PortableMsmCorrect` contract. All verifier consumers discharge the portable MSM contract internally. The lane pairing contract is also proved. Scalar pairing uses the scoped blst law.

### Verifier MSM8 kernel

`lean/LeanBlsSimd/Msm8/` proves the verifier's eight-lane G1 linear combination. It is a verifier internal, alongside the interpolation kernel. The extender uses the shared Fr FFT proofs but does not call MSM8.

The refinements cover generated word arithmetic, scalar conversion, point stores, signed digits, buckets, affine batches and complete projective sums. They establish successful `Result` execution under internal representation and size invariants. The group proofs connect these results to the specification's weighted sum.

`PlainWords.lean` converts reduced blst scalars to ordinary little-endian words, preserving their values and length. Multiplication by 16 cancels blst's Montgomery factor `2^256` through the Fr kernel's factor `2^260`. Finite filtering removes paired infinity inputs without changing the sum. `G1AffineValid` supplies subgroup validity; reduced scalar encodings supply values below `2^255`.

`Glv.lean` checks the generated constants and carry arithmetic against `Model/Glv.lean`. The constants satisfy `λ = z² − 1` and `r = λ² + λ + 1`. The model uses the exact fixed-point reciprocal `Z2_OVER_R` and threshold `HALF_R_UP`. For `0 ≤ k < 2^255`, signed outputs satisfy `k₁ + λ*k₂ ≡ k (mod r)` and `|k₁|, |k₂| < 2^127`. `GlvGroup.lean` proves `σ(P) = [λ]P` for subgroup points, using the existing Scott completeness theorem. The split therefore preserves each point's scalar contribution.

`Store*.lean`, `Conversion.lean` and `AffineInput.lean` connect generated loads and writes to represented points. Point `i` occupies rows `2*i` and `2*i+1`, holding its x and y coordinates as eight radix-`2^52` words. Conversion changes the coordinate Montgomery factor from blst's `2^384` to Fp8's `2^416`. The proof checks the literal `TWO_POW_448_MOD_P = 2^448 mod p`. The first `n` entries hold signed original points; the next `n` hold signed endomorphism images. A reference uses its low 31 bits as the point index and bit 31 as a negation flag. Stores write lanes in order, so repeated indices retain the last write. Padding repeats the final job and preserves its result.

`SignedDigits.lean`, `Buckets.lean` and `Fill.lean` prove the generated signed-digit trace and exact ordered bucket contents. The selected widths are 4, 6 and 8 bits, with 32, 22 and 16 windows respectively. These windows cover the carry above a 127-bit half. A digit exactly at the half-window threshold remains positive. Queue reductions preserve each bucket's group sum while allocating or reusing independent output slots.

Affine batches accumulate nonzero x-coordinate differences into inversion chains. `Inversion.lean` proves that the generated exponent chain, including its final multiplication, computes exponent `p−2`. Batch invariants establish nonzero factors before inversion and justify unwinding the product. Equal x-coordinates reject a batch before inversion. The caller refills the original buckets and sums them using complete projective additions. Those additions cover infinity, doubling and cancellation.

`WindowSum.lean`, `Flatten.lean` and `Lanes.lean` recover the bucket and window weights. Bucket `b` contributes weight `b+1`; window `j` contributes `2^(bits*j)`. `Refines.lean` composes the generated chunk loop without an input-length bound. `Msm8.lane_zero_pointRep` in `OutputBridge.lean` converts a lane representing a valid subgroup target through generated `lane_zero_in_blst`. Its `G1Rep` conclusion preserves infinity and affine coordinates without requiring identical Jacobian representatives. `Msm8.msm_refinement` in `Refines.lean` identifies that target with the specification's `G1.msm`.

`Bounds.lean` proves the counter bounds for a nonempty chunk with `n ≤ 2^24` finite points. There are at most `2*n` references per bucket and `2*n*windows` references overall. The store reserves `2*n + n*windows` points. `MsmBounds.fill_chunk_bounds` returns per-bucket and total-reference bounds, together with a `Resources` certificate. That certificate bounds `2*(2*n+n*windows)` and `n*windows+15` below `2^32`, and `2*n+n*windows` below `2^31`. These are internal chunk bounds, not an additional public input-length premise.

The generated outer MSM loop processes chunks of at most `CHUNK = 4096` inputs. It combines their results with complete G1x8 additions. The constant satisfies `CHUNK ≤ 2^24`, establishing the finite-point bounds used by `Bounds.lean`. Group-sum composition covers every representable aligned input length; the public theorem adds no chunk-size premise. Empty inputs and chunks containing only infinity points contribute the identity. Chunking does not introduce a blst fallback.

### Field and point representations

`frEncode` uses four little-endian 64-bit limbs for the reduced Montgomery residue `x * 2^256 mod r`. Scalar laws apply to this encoding, not arbitrary limb arrays. The extraction and representation target blst's 64-bit platform layout, `limb_t = u64`; they do not describe a 32-bit-limb build.

`G1Rep` relates a Jacobian result to the spec by its infinity status and affine coordinates. It does not require blst and the spec to choose the same Jacobian representative. Affine coordinates use six reduced Montgomery limbs with `R = 2^384`. The pairing contract calls the spec's `pairingCheck`; both implementations omit pairs with either a G1 or a G2 point at infinity. `Sha256.sha_correct` proves both streaming implementations agree with specification SHA-256, and challenge refinement reaches `Fr.hashToBlsField` through reducing scalar decoding. The proved canonical scalar decode rejects integers greater than or equal to `r`. Portable G1 adapters retain the representation and validity conditions needed at their call sites. `G1Valid` checks subgroup membership on the Jacobian representative. `G1Validity.lean` transports this predicate through `G1Rep`, including arbitrary infinity representatives such as blst's all-zero triple, and proves that valid points have valid affine encodings. `G1Arithmetic.lean` proves closure and point equivalence for addition, negation, doubling and scalar multiplication under the same validity predicate. `G1Msm.lean` extends these results to multi-scalar multiplication, using upstream's weighted-sum theorem after normalizing infinity inputs. `G1Compression.lean` lifts EthLib's `G1.uncompress_compress` to `G1Valid`, preserving infinity status and affine coordinates. It handles arbitrary infinity representatives locally. `PairingRepresentation.lean` transports the pairing inputs across these representative changes.

### Manual blst Fr audit

The manual blst v0.3.16 audit covers Fr arithmetic and input-conversion wrappers in `blst/src/exports.c`. It includes final conditional subtraction in `blst/src/no_asm.h::mul_mont_n` and `add_mod_n`. It also covers x86-64 ADX assembly and `blst/src/recip.c::reciprocal_fr`. Addition, subtraction and Montgomery multiplication preserve reduction on reduced inputs. `blst_fr_from_scalar` handles a full 256-bit digest because its other operand is a reduced Montgomery conversion constant. The product is therefore below `r * 2^256`. This audit supplies background evidence about blst. Generated portable scalar contracts are established by their Lean proofs.

### Setup connection

`embeddedSetup` is the pinned spec's private `TrustedSetup.buildEmbedded` value, accessed with Batteries' `open private`. `embedded_setup_matches` equates the verifier's 64 compressed G1 encodings and proves G1 validation. It also proves successful G2 decoding and subgroup membership at indices 0 and 64.

The proof compares G1 Rust constants with the pinned specification using separate kernel checks for each row. Generated setup stores the G1 vector; IFMA pairing uses the fixed line table. Scalar pairing uses certified extracted affine G2 literals. `SetupPoints.lean` certifies all 64 G1 points and both G2 points with explicit witnesses. `SetupArithmetic.lean` supplies structural exponentiation and multiplication, plus decoding equations parameterized by square-root results. Each numerical square-root or inverse certificate is checked separately before composing the decoder proof. `SetupValidity.lean` proves `setup_g1_affine_valid` from the G1 certificates. These stages avoid reducing the closed G2 decoder and its square roots together. Certificates use only the three standard axioms and require no separate setup-file assumption. The specification's connection to Ethereum's intended ceremony remains trusted.

### Specification target and evidence

The specification target is [ethereum/EthLib at `98395150`](https://github.com/ethereum/EthLib/tree/98395150e9eb6a11fd85022bee7ea9da9a8e3760). The package is `EthLib`; cryptography modules use `EthLib.Cryptography`. Lean and Mathlib are v4.35.0. Verifier and extender headlines retain the upstream definitions as their specification targets.

The pinned EthLib tree contains all 12 KZG vector suites, including 32 batch-verifier cases and 11 `compute_cells` cases. These vectors supply finite evidence; they do not prove equivalence to an independent specification.

EthLib generates vectors by executing its compiled Lean specification and writing the results. Its [`bindings/python/kzg.c`](https://github.com/ethereum/EthLib/blob/98395150e9eb6a11fd85022bee7ea9da9a8e3760/bindings/python/kzg.c) calls Lean functions. The Lean specification has no `implemented_by` or `extern` overrides. Those vectors therefore exercise the same target as the proofs. The c-kzg comparisons in [`src/kzg/tests.rs`](../src/kzg/tests.rs) provide evidence from another implementation.

### Evidence and controls

The Rust [`spec_vectors.rs`](../src/kzg/spec_vectors.rs) tests the pinned `verify_cell_kzg_proof_batch`, challenge and `compute_cells` vectors. [`tests.rs`](../src/kzg/tests.rs) compares with the c-kzg reference implementation. These finite cases exercise the implementation against independent recorded or reference results; they do not discharge the universal generated-component premises. `compute_cells` checks exercise `CellExtender` against the same pinned specification as its proof.

The KZG source has no separate hash table. `extract.sh --check` checks all generated types, literals and functions, including KZG, using the comparison boundary above. The BLS hash table is an additional source inventory.

Paths below are relative to `lean/controls/`.

| Control | Checked boundary |
|---|---|
| `ContractSamples.lean` | Interpreter samples of generated Fr/byte operations, both portable Fp paths and both SHA implementations, with wrong-result controls. |
| `msm-mutation-check.py` | Run after `lake build`. Source mutation control: original and reformatted portable finish schedules compile; skipping rejected-round refill fails `finish_correct` with an unsolved goal. |
| `MsmSamples.lean` | Interpreter samples of actual portable MSM with reused scratch, infinity, cancellation and a wrong-weight control. `[G,G]` with scalars `[1,1]` must reject a generated pair round and return `2G` through the MSM fallback. |
| `PortableMsm.lean` | Generated signed-reference loads reject an omitted negation; writes preserve other slots. Equal-x jobs at the first or a later position reject a successful-round result without changing the store. The fifth preparation job checks reuse of the first chain and rejects an omitted prefix update. A complete batch permits overwriting its own input and rejects an omitted reverse write. A generated queue round preserves an odd carry and rejects a dropped carry; reusable references need no spare slot. A rejected pair-round loop exits with its rejected batch still nonempty. The input filter rejects a scalar whose high bit violates its bound. Bucket counting rejects a dropped increment, and chunk counter bounds are checked. |
| `LaneTowerCapacity.lean` | Actual operands above `1024p` satisfy the tower product capacity; a too-small offset produces a negative signed value. |
| `pairing-table-mutation-check.py` | After the build, checks a changed limb, tangent numerator, normalizer sign and denominator condition against the live table's kernel certificate. Original and reformatted tables pass. |
| `pairing-product-mutation-check.py` | Refinement proofs reject mutations to generated infinity filtering, lane flags, conversion, packing, Miller loops and set products. They also reject mutations to final-exponentiation hand-off, fallback and owner lifecycle. Original and reformatted declarations pass. The suite excludes equivalent dispatch swaps and forced fallback, which preserve the verdict contract. |
| `pairing-loop-mutation-check.py` | Run after the build. Mutations cover generated lane permutations, table rows, presence selection/complement, bit decrements, final conjugation and omitted final exponentiation. Each fails the actual lane refinement proofs with ordinary proof errors. Original and reformatted definitions pass. |
| `FinalExponentiation.lean` | The easy output at zero fails unconditional Φ12 membership. The numeric exponent differs without the factor of three. The generated lane final-exponentiation verdict rejects zero and accepts one. |
| `final-exponent-mutation-check.py` | Run after the build. Changes to the generated multiplication base, parameter conjugation, square input and final product fail their named refinement proofs with ordinary errors. Original and reformatted definitions pass. |
| `PairingMiller.lean` | A normalized raw value of p holds field zero. The generated zero-mask call sets all bits, and both pairing presence bits are false. |
| `lane-tower-mutation-check.py` | After the build, generated arithmetic, packing, product-loop, square and line mutations fail with proof errors. Checks also cover conjugation, Frobenius selection, cyclotomic recombination, inverse determinant sign and identity-mask coverage. Original and reformatted definitions pass. |
| `TowerField.lean` | Total inverse and zero-power behavior, zero rejection and field/target-group axioms. |
| `Cyclotomic.lean` | A unitary `−1` outside Φ12 makes the cyclotomic formula return the wrong square, including in the field model. |
| `tower-mutation-check.py` | After the build: original/reformatted sources pass; changed Fp4 pairing, output sign, inverse sign and Montgomery radix fail named proofs. |
| `KzgBlstBoundary.lean` | Constant-false decoder and pairing observations violate the scoped laws at infinity. A specification-defined dictionary witnesses their consistency together. This does not prove blst satisfies them. Arbitrary observations permit IFMA verification. |
| `KzgRuntimeBoundary.lean` | KZG headline and runtime dependency closures exclude the opaque G2 decoder, typed-point externals and the signature pairing external. Decoder headlines exclude the typed-point and pairing externals. The signature-path, constructor, point-operation and pairing controls reach their expected externals. IFMA verifier/G1 and extender headline types exclude both blst laws. Adding either law is rejected. |
| `ShaGenerated.lean` | Generated updates reject a dropped length wrap; finish rejects a missing padding marker and reversed digest bytes. The proved `ShaCorrect` is checked with no premise. |
| `ShaExtensions.lean` | The ABEF/CDGH packing definitions differ on the fixture. Instruction samples distinguish an omitted shuffle, reused message words and omitted byte swapping. |
| `ShaPortable.lean` | Generated byte loading, schedule expansion and rounds reject reversed byte order, the wrong sigma function and a zeroed round constant. |
| `ShaStreaming.lean` | The shared streaming invariant excludes missing pending bytes and incorrect stored lengths. |
| `ShaSpec.lean` | Local fixtures distinguish round constants and feed-forward. Padding equations check the 55/56-byte boundary and bit-length wrap; a UInt64 fixture checks byte-count wrapping. |
| `sha-mutation-check.py` | Run after `lake build`. Copies `Spec/Sha256.lean` and changes the round operand from `d+t1` to `c+t1`. Requires an unsolved goal in `compressBlock_eq`; timeouts fail the harness. Unchanged and reformatted sources must compile. |
| `decoder-mutation-check.py` | Run after `lake build`. Mutates the ordinary decoder zero-x check and Scott comparison y sign. The generated-code and specification ties must reject them with proof errors. Timeouts fail; unchanged and reformatted copies must compile. |
| `KzgStreamingSha.lean` | Constant-zero hashing is rejected; changing chunk boundaries preserves the observed digest, and both proved generated SHA paths agree. |
| `ExtractedLiterals.lean`, `ShaIntrinsics.lean` | Hoisted literals equal the extracted values; SHA/SSE intrinsic fixtures and mutations check packing, lane order and round operands. |
| `PortableFpWords.lean` | Generated carry, subtraction and wide-product boundary witnesses retain the carry, borrow and high word. |
| `PortableG1Pair.lean` | Equal-point addition flags only the affected lane. One flagged lane is recomputed by the scalar test while the unflagged lane uses its chain; omitting that fallback rejects the generator. |
| `PortableDecode.lean` | Generated scalar decoding accepts canonical infinity and rejects a nonzero infinity tail or x = 0. It enforces x < p and preserves canonical nonzero x. Paired decoding preserves the order of an accepted infinity and a rejected zero-x encoding. |
| `PortableG1.lean` | Generated doubling preserves infinity; complete projective and affine addition handle opposite points. The scalar Scott test accepts the generator and rejects a false result. |
| `PortableFpInverse.lean` | Halving retains the incoming high bit; odd coefficients require the modulus correction; the one test checks upper words. Inversion covers zero and one and changes two. A zero factor in the four-element batch yields four zero outputs; four ones remain ones. |
| `PortableFpPowers.lean` | Conversion removes the Montgomery scale; sign tests distinguish 1 and −1; zero roots succeed and the pair result retains both validity bits. |
| `PortableFpCorrect.lean` | Canonical wraparound and both BMI2 wrappers preserve Montgomery encoding; plain-one products and noncanonical modulus representatives are rejected. |
| `PortableFpReduction.lean` | Generated reduction maps the modulus to zero; the split product retains a high word shifted across the six-word boundary. |
| `FrScalar.lean` | Generated scalar refinements exclude dropped carries, missing borrows, a lost fifth word, incorrect reduction and wrong Montgomery encodings. |
| `FrBytes.lean` | Canonical decoding rejects r; digest reduction accepts the maximal 256-bit value. Generated decoding and serialization exclude reversed bytes. |
| `InverseRoots.lean` | The generated inverse table excludes forward ordering; the root-order proof rejects a wrong inverse exponent. |
| `SetupLiterals.lean` | The certified G2 literal excludes the wrong generator sign. |
| `setup-literals-check.py` | Both extraction modes require all 48 production Rust G2 limbs to match their Lean transcription. A single-limb mutation in either literal is rejected. |
| `KzgMathematical.lean` | Bit reversal, inverse coset-shift direction and inverse FFT scaling. |
| `KzgSetupBoundary.lean` | Replacing embedded G2 point 64 with infinity violates the setup match. |
| `InterpolationKernel.lean` | Wrong inverse-size shift factors or used-column flags violate the generated contracts. Unnormalized first products violate bounded DIT input. Noncanonical cells are rejected. Canonical acceptance and normalization supply positive controls. |
| `Msm8.lean` | Wrong bucket indices, digit signs, GLV constants and window weights violate their laws. Skipping equal-x rejection or the inverse chain's final multiplication fails concrete controls. Queue aliasing, allocation, repeated-job padding and scalar-word length have positive and negative cases. |
| `ExtenderMathematical.lean` | Extender input/output bit reversal, coset shifting, forward FFT direction and inverse FFT scaling at the blob size. |
| `ExtenderLayout.lean` | First-half copying, the extension's cell-64 offset, rejection of noncanonical blobs and output preservation on rejection; generated decoding rejects an all-`ff` blob. |
| `ExtenderKernelBoundary.lean` | The generated range mask rejects raw out-of-range values. Permutation uses bit 3 and ignores higher bits. Multiplier construction requires its factor of 16. Kernel byte encoding and portable scalar serialization are both proved. |
| `ExtenderKernelBytes.lean` | Missing reduction or canonicalization violates generated contracts. Reversed bytes, a missing cell-64 offset and a cleared first half also violate them. |
| `Fr8Swap.lean` | A wrong byte-swap mask changes the generated vector result. |
| `Fr8Words.lean` | A wrong unpacking shift or decode/encode block-permutation index changes the generated result; the controls pin the correct expressions to the extraction. |
| `ExtenderKernelFft.lean` | Swapped short-stage twiddles and a shifted wide-table read violate the generated table invariant. Semantic controls distinguish skipping a nonunit short-stage product, omitting either block transpose, and substituting inverse DIF/forward DIT without the required bit reversals. |
| `ExtenderKernelTranspose.lean` | A copied generated transpose network is pinned by definitional equality; changing its first shuffle index changes an observed output lane. |
| `ExtenderKernelShortStage.lean` | A copied generated DIT short-stage pipeline body is pinned by definitional equality. A wrong twiddle offset changes the pending product. |
| `SignedLimbs.lean` | Raw addition needs the stated limb bound. Replacing the arithmetic carry shift with a logical shift changes the represented integer of a fixture with a negative limb. |
| `ExtenderKernelLazy.lean` | Omitting the final reduction from generated addition leaves `2r` outside the reduced range. A noncanonical unit multiplier makes the raw product exceed `2r`. Numeric examples check headroom for `Lazy 34 370`; a boundary check rejects `36r < 2^260`. |
| `ExtenderKernelPipeline.lean` | A copied `first_of_pair` pins to the extraction. A wrong stride aliases consecutive butterflies and changes their operand indices. |
| `ExtenderKernelRange.lean` | At `h = 1`, valid short-stage inputs at `2r−1` produce `4r−2`, outside `LazyRep (4*h−1)`. |
| `LeftShiftIntrinsic.lean` | Left shifts preserve lanes, discard overflow, and return zero for counts at least 64. Mutations to counts, lane order and overflow handling fail. |
| `KzgStrictAxioms.lean` | The shared proof, runtime consumers and KZG negative controls use only the three standard axioms. |
| `KzgSetupAxioms.lean`, `KzgRefinementAxioms.lean`, `KzgRepresentationAxioms.lean`, `KzgSpecBridgeAxioms.lean`, `KzgPolynomialAxioms.lean` | Scoped axiom checks for setup, refinement, representations, spec bridge and interpolation. |
| `extraction-check.py` | Both modes pass without `lake` or build artifacts; reinserting SHA, decoder or MSM mutation hooks fails. Unchanged output, interleaved function families and numeric source-span changes pass. Changed rows, lanes, step order, helper types or attributes, malformed literals and a wrong `full` count are rejected. So are body edits and missing or duplicated entry points. Both extraction modes enforce raw expansion equality; default extraction updates all three generated files and the Lean equality control. |

For layer-specific build commands, see the [KZG scoped checks](lean/README.md#scoped-checks).

`Spec/PairingEquations.lean` states the successor equation for `millerSteps`, unfolds `millerLoop`, and expresses `pairingCheck` as an array fold. `controls/PairingEquations.lean` prints those theorems' axioms and the Fp2 power transport's axioms. `toField_finalExponentiation` in `Spec/FinalExponentiation.lean` relates final exponentiation to the total field power.

The extender's mathematical controls distinguish the actual 4096-element transform stages using field-array witnesses. Its layout controls compare the generated copy loop and output-update function, plus mutations of the model's error branches. A further control constructs an extender and proves its generated decoder rejects an all-`ff` blob. They do not rerun a mutated Rust implementation.
