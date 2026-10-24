# Formal proof of BLS decoding and KZG cell operations

One Lean project checks the Charon/Aeneas translation of `silver_crypto_simd`'s G1 and G2 batch decoders, `kzg::CellBatchVerifier` and `kzg::CellExtender`. The verifier headlines refine the x86-64 extraction under two remaining correctness premises for portable MSM and pairing. Scalar and base-field arithmetic, scalar bytes, both streaming SHA implementations and portable G1 decoding are proved. The extender has no component-contract premises. The two remaining contracts are proof obligations, not axioms. The [trust list](#what-a-reader-must-trust) explains the connection from generated Lean semantics to Rust.

The BLS scope is point decoding and subgroup checks, including the proved IFMA kernels and Scott criteria. G1 portable decoding is proved by `Portable.Decode.g1_decoder_correct`, which constructs `G1DecoderCorrect`. G2 fallback retains the opaque blst decoder and its explicit agreement premise. Full BLS signature verification is outside the scope. KZG verification and extension include constructors, `Default`, output writes, persistent state and repeated calls.

The project pins the `gattaca-com/EthLib` fork's total pairing definitions, with Lean and Mathlib at v4.29.1. Its extraction includes portable implementations, independent CPU feature observations and separately compiled setup literals. The Lake package is `lean_bls_simd`; its library is `LeanBlsSimd`.

- [What is proved](#what-is-proved): [G1 wrapper](#g1-wrapper), [G2 wrapper](#g2-wrapper), [G2 kernel](#g2-kernel), [KZG verifier](#kzg-verifier), [KZG extender](#kzg-extender).
- [Using the public results](#using-the-public-results).
- [What a reader must trust](#what-a-reader-must-trust).
- [Reproduction](#reproducing-the-proof-and-checks) and [maintenance](lean/README.md).
- [BLS internals](#bls-proof-internals) and [KZG internals](#kzg-proof-internals).

## What is proved

Both public BLS wrappers require one output slot per input. On unequal lengths, the generated functions return `fail .assertionFailure`; their mismatch theorems do not retain Rust's panic text, `"one verdict slot per input"`.

### G1 wrapper

`UncompressG1.uncompress_in_g1_eq_spec` covers the generated public wrapper, including output writes and all portable singleton and pair calls:

```lean
theorem uncompress_in_g1_eq_spec [RuntimeFeatures]
    (inputs : Slice (Array U8 48#usize)) (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g1 inputs out = ok result ∧
      result.val.length = inputs.val.length ∧
      ∀ i : Fin inputs.val.length,
        result.val[i.val]? = some (specVerdict inputs.val[i.val])
```

An index uses IFMA when SIMD is available, it belongs to a complete eight-input chunk, and its undecided bit is clear. `G1DecoderCorrect` states exact specification verdicts for the actual generated portable singleton and pair decoders. `Portable.Decode.g1_decoder_correct` proves those laws; the wrapper refinement combines them with the proved IFMA kernel. It has no G1 blst observation or `BlsExternals` parameter. The compatibility name `uncompress_in_g1_eq_spec_or_blst` remains available, with specification verdicts on both routes and no decoder-contract premise.

The G1 specification verdict calls `bytesToKzgProof`, decodes accepted bytes with `G1.uncompress`, and normalizes through `G1.toAffine`. Each coordinate has six little-endian Montgomery words with R = 2^384. Infinity has both coordinates zero. The bridge lemmas relate acceptance to both `bytesToKzgProof` and `bytesToKzgCommitment`.

### G2 wrapper

`UncompressG2.uncompress_in_g2_eq_spec_or_blst` covers the generated public wrapper:

```lean
theorem uncompress_in_g2_eq_spec_or_blst [RuntimeFeatures] [BlsExternals]
    (inputs : Slice (Array U8 96#usize)) (out : Slice (Option blst.blst_p2_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g2 inputs out = ok result ∧
      result.val.length = inputs.val.length ∧
      ∀ i : Fin inputs.val.length,
        result.val[i.val]? = some
          (if usesKernelAt inputs i.val then specVerdict inputs.val[i.val]
           else BlsExternals.uncompressG2 inputs.val[i.val])
```

`usesKernelAt_iff` characterizes the route exactly: SIMD is available, the index is in range, its chunk has at least three inputs, and its lane's undecided bit is clear. Chunks contain at most eight inputs. A short kernel chunk repeats its last input to fill eight lanes; only the original lanes are written back. Smaller chunks, undecided lanes and calls without SIMD use the same scalar external.

Under `UncompressG2.BlstMatchesSpec`, `uncompress_in_g2_eq_spec_list` returns `inputs.val.map specVerdict`, and `uncompress_in_g2_eq_spec_model_list` expresses the result in model types as `inputs.val.map (G2Spec.verdict ∘ ofArray ofU8)`. The pointwise corollary and `uncompress_in_g2_eq_blst` are also available. The premise requires exact agreement on every 96-byte input, including acceptance, affine limbs and infinity.

`G2Spec.verdict` calls the pinned specification's `G2.uncompress` and `G2.inSubgroup`. Its affine conversion calls `G2.toAffine` before writing the coordinates in blst's layout. `G2Spec.verdict_some_iff` and `UncompressG2.specVerdict_some_iff` characterize acceptance and exact limbs. `G2Spec.infinity_verdict` proves that canonical compressed infinity returns `some` of the all-zero affine limbs. The decided-lane bridge `decompress_eq_verdict` uses `G2Spec.blstLimbs_eq_of_z_one` to relate this affine conversion to the kernel's conversion of decoded finite points.

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

Here `l : Fin 8` selects one of the eight lanes. The expression returns `some point` for an accepted lane and `none` for a rejected lane. On the right, [ethereum/EthLib](https://github.com/ethereum/EthLib) decodes with `G2.uncompress` and checks subgroup membership with `G2.inSubgroup`. These are the signature decoding and subgroup checks used by `coreVerify`; the theorem does not cover the rest of signature verification, which also validates the public key, hashes the message to G2, and checks a pairing.

The conversions make the representation on each side explicit. `ofArray (ofArray ofU8)` converts Aeneas's input arrays to `Vector`s of bytes. `ofBatch` converts each returned mask through `ofU8` and each point through `ofBlstP2Affine`. `toBytes` passes the lane's 96 bytes unchanged. `blstLimbs P` expresses P's coordinates in blst's `blst_p2_affine` layout.

The left side is how `decompress_g2_chunk` in `mod.rs` reads one lane. `Mmask8.and_one_shiftLeft_ne_zero` shows that its test `mask & (1 << lane) != 0` is `testBit`.

`decompress_extracted_eq_spec_complete` combines two results:

- `decompress_refines`, in `lean/LeanBlsSimd/Refines/DecompressG2.lean`: on every input, the generated `decompress` returns `ok` of the model's result, converted back by `toBatch`. This unconditional equality covers every field, including points on rejected and undecided lanes. The other files in `Refines/` establish the corresponding equalities for the functions it calls.
- `decompress_eq_spec`, in `lean/LeanBlsSimd/Proofs/Kernel.lean`: the same claim about the model's `decompress`, over `Vector`s. Its completeness argument is described in [G2 kernel proof and completeness](#g2-kernel-proof-and-completeness).

### KZG verifier

`LeanBlsSimd.Kzg.verify_eq_spec` proves that the generated constructor succeeds and establishes the invariant. Every state satisfying that invariant returns the embedded specification's Boolean verdict on every representable input. The next state preserves the invariant, including after rejected batches. Specification errors become `false`; length mismatches, invalid encodings and out-of-range indices are included.

```lean
theorem verify_eq_spec [cpu : RuntimeFeatures]
    (hmsm : PortableMsmCorrect) (hpairing : PairingCorrect) :
    ∃ initial, verify.CellBatchVerifier.new = ok initial ∧ StateInvariant initial ∧
      ∀ (v : verify.CellBatchVerifier), StateInvariant v →
      ∀ (i : Input), i.Representable →
      ∃ (verdict : Bool) (next : verify.CellBatchVerifier),
        i.generated v = ok (verdict, next) ∧ StateInvariant next ∧
        Model.rejectErrors i.embeddedSpec = verdict
```

The two remaining premises are named `Prop`s about actual generated functions:

| Contract | Required component behavior |
|---|---|
| `PortableMsmCorrect` | Generated portable MSM agrees with `G1.msm` for valid affine points, canonical ordinary scalar words and arbitrary scratch. |
| `PairingCorrect` | Lane and portable pairing functions agree with the two fixed-G2 specification pairings, under their point and table representations. This includes `PAIRING_LINES` encoding the lines of [s^64]G2 and −G2. |

`ComponentContracts` bundles these premises internally for composition. It is not an operation dictionary. No KZG headline takes `BlstCorrect` or an opaque G2 decoder.

`RuntimeFeatures` supplies independent `simdAvailable`, `shaAvailable` and `bmi2Available` Booleans. Construction selects the interpolation kernel and the `CurveWork` route from `simdAvailable`. SHA dispatch reads `shaAvailable`, while portable field multiplication can select BMI2 independently. The premises and headlines quantify over any fixed feature assignment. The model covers all four combinations of interpolation and curve-work routes independently of the eight feature assignments. Real execution requires hardware support for every instruction on the selected routes; constructor-produced states align the stored routes with stable CPU observations.

`CurveWork.Portable` stores its pairing table alongside MSM scratch. `PortableLinesRep` interprets every coefficient of that table as a canonical Montgomery value matching the fixed extracted lane table. `PairingTableBounds.lean` checks each of its 544 lanes for normalized limbs and a canonical value. `pairingLines_new_refinement` proves the actual nested constructor using the proved portable Fp contract, packing and radix-conversion lemmas; it does not require `PairingCorrect`. `CurveWork.sum_frame` proves that successful MSM preserves the exact table and the stored route.

`new_returns_ok` has no component-contract premises. `default_eq_new` transfers that result through `Default`. `new_returns_ok_route` characterizes the constructor's two stored choices; `Routes.verify_preserves_routes` preserves them through successful calls. `StateInvariant` additionally fixes the setup, cosets, interpolation tables and buffer lengths, while permitting earlier scratch contents. Replacing curve work requires a valid replacement table: `stateInvariant_curveWork` takes `CurveWorkInvariant work`. It is not an unrestricted invariant equivalence for arbitrary replacement work.

`verify_eq_upstream` has the same component premises and execution/state conclusion for the upstream `verifyCellKzgProofBatch` action. It additionally requires `TrustedSetup.get! = pure embeddedSetup`. The embedded-setup headline has no runtime-loader premise. The G2 setup points are fixed mathematical constants with proved decoding and subgroup certificates. Generated KZG execution consumes the fixed pairing table without calling `uncompress_in_g2_blst`.

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

Every call returns `ok`. Success writes the specification's exact cell bytes. Rejection agrees with a specification error and leaves all output cells unchanged. The invariant fixes the scalar roots, inverse roots, inverse size and shift powers, the two scalar scratch-vector lengths, and the optional kernel's FFT tables, shift multipliers and buffer lengths. It allows scratch contents left by earlier successful or rejected calls.

The headline and constructor have no component-contract premises. Scalar arithmetic and byte conversion are proved for the generated functions. No group, hash, pairing, G1-decoder or runtime setup-loader premise is involved. `Extender.default_eq_new` covers `Default`, `Extender.model_eq_spec` equates the full model result with the upstream action, and `Extender.model_accepts_iff` characterizes canonical input.

`new_dispatch_refinement` proves that construction stores a kernel exactly when `simdAvailable` is true. Each `compute` dispatches on that stored option. The internal kernel computation proves its own arithmetic and canonical byte encoding. The public headline composes the portable scalar proofs with that kernel proof. `scalar_constructor_exists` and `kernel_constructor_exists` prove both constructor routes without component premises.

## Using the public results

### Runtime features and the G2 external

Supply `[silver_crypto_simd.RuntimeFeatures]` to entry points that observe CPU features. `silver_crypto_simd.bls.BlsExternals` contains only the opaque G2 decoder. G2 wrapper results additionally use that class and, for exact specification equality, `UncompressG2.BlstMatchesSpec`. G1 and KZG consumers do not require it.

### BLS decoding

Import `LeanBlsSimd.Refines.UncompressG1` for the G1 wrapper:

```lean
theorem uncompress_in_g1_eq_spec_list [RuntimeFeatures]
    (inputs : Slice (Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g1 inputs out = ok result ∧
      result.val = inputs.val.map specVerdict
```

`specVerdict_some_iff` relates an accepted affine result to `bytesToKzgProof` and exact decoded limbs. The pointwise and model-type list variants are also available. `controls/G1Consumer.lean` and the independent `controls/downstream/G1Smoke.lean` apply these public results across consumer-owned structures without a decoder-contract premise.

For G2, import `LeanBlsSimd.Refines.UncompressG2` and use `uncompress_in_g2_eq_spec_list` with `[RuntimeFeatures]`, `[BlsExternals]` and `UncompressG2.BlstMatchesSpec`. Without the agreement law, `uncompress_in_g2_eq_spec_or_blst` characterizes kernel verdicts and opaque fallback observations. `controls/G2Consumer.lean` and `controls/downstream/G2Smoke.lean` exercise the list interfaces and transport across independent structures.

### KZG verification

Import `LeanBlsSimd.Kzg.Statements`. With the two remaining contracts in scope, apply:

```lean
verify_eq_spec hmsm hpairing
```

Use `new_returns_ok` for construction alone, or `glue_refinement` with a `ComponentContracts` bundle for the intermediate model. `verify_eq_upstream` additionally takes the runtime setup-loader hypothesis.

For individual generated calls, import `LeanBlsSimd.Kzg.Refines`:

| Wrapper | Cell interface |
|---|---|
| `decode_cells_refines` | Canonical-decoding verdict on both routes; evaluation-scratch equality when `v.kernel = none`. |
| `interpolation_commitment_refines` | `InterpolationKernel.CellsRep cells evals`, with evaluation-scratch equality conditional on `v.kernel = none`. |
| `pairing_holds_refines` | The same cell relation and conditional scratch premise, with the fixed-target specification pairing verdict. |

`CellsRep` requires matching batch lengths and 64 evaluations per cell. Each 32-byte element must decode canonically through `bytesToBlsField`. The headline derives this relation from successful cell checks and discharges the scratch premise internally.

`Kzg/Lincomb.lean` supplies `verify_lincomb_refinement` and its raw-input variant for the actual `verify.CurveWork.sum`, using `PortableMsmCorrect` and the proved ordinary-word conversion. Lane-only refinements use the proved MSM8 implementation and need no component premise. `CurveWork.sum_frame` preserves the exact stored table and route, enabling invariant preservation without restricting scratch to constructor-reachable values. The interpolation adapters specialize these statements to the embedded setup.

`controls/downstream/KzgSmoke.lean` applies the generated-runtime headlines conditionally on the named contracts. This checks the consumer interfaces, not the truth of their pending premises.

### Decoder bridge and component premises

`Kzg/Decoder.lean` proves `specVerdict_eq_bls`: KZG and BLS G1 verdicts agree as optional affine points, including limbs and infinity. The KZG batch adapter composes directly with the shared, proved generated G1 wrapper. There is no copied runtime decoder dictionary at this boundary.

The two remaining contracts concern fixed generated definitions. `FrScalar.fr_correct` proves `FrCorrect`; `FrScalar.fr_bytes_correct` proves `FrBytesCorrect`. Neither scalar law is a consumer premise. The Montgomery invariant bounds every row by `a + r`. Only the first operand must be below `r`; the second may contain any four words. The proof retains the fifth multiply-add word and bounds each division result before eliminating truncation. Exact `frEncode` equalities cover addition, subtraction and multiplication. Byte proofs cover canonical decoding, arbitrary digest reduction, ordinary scalar words and exact big-endian serialization. Canonical decoding rejects `r` itself. Digest reduction preserves the generated operand order, with `R_SQUARED` first.

`Portable/Fp/` proves canonical six-word Montgomery arithmetic at R = 2^384, the exact wide product and reduction, ordered and modular subtraction, binary inversion, exponentiation, square root and root sign. Its CIOS proof permits any six words in the second operand when the first is canonical. Binary inversion returns zero for zero input. The generated four-input batch inverse uses one product inverse; if any input is zero, all four outputs are zero. Both BMI2 dispatch branches use the proved arithmetic.

`Portable/G1/` proves complete scalar Jacobian operations and the two-lane formulas and chains. Each exceptional lane is recomputed by the scalar Scott test; an unflagged lane agrees with the complete group operations. `Portable/Decode/` connects flags, canonical x, square root and sign to the existing encoding verdict, proves rejection of the order-3 x = 0 and order-2 y = 0 cases, and accepts only canonical infinity. G1 uses the proved `G1Spec.scott_sound` and `G1Spec.scott_complete`; G2 retains the proved `scott_complete : ScottComplete`. No public theorem takes a Scott-completeness premise. The production extraction includes `G1.from_affine`; the Rust `G1.to_affine` helper is test-only and absent from that extraction, so its Rust body is outside these generated-function proofs.

`controls/ContractSamples.lean`, `MsmSamples.lean` and `PairingSamples.lean` evaluate the generated functions against the specification. These `#eval` checks use Lean's interpreter outside the proof kernel. They provide finite evidence, not proofs or satisfiability witnesses for the contracts. Assertions make a mismatch fail the build.

Samples cover scalar carries and canonical-byte boundaries, reducing 2^256−1, both BMI2 field paths, SHA padding and chunk boundaries, and reusable MSM scratch. Portable pairing includes a nonzero true case: `(G1.generator, [s^64]G1)` against `([s^64]G2, −G2)`, using the pinned setup. Negating its second G1 point must produce false. The sample checks the specification verdict and generated verdict separately. Lane pairing is not sampled here. G1 decoding has the separate generated-code differential corpus.

### KZG cell extension

Import `LeanBlsSimd.Kzg.Extender.Statements` and apply:

```lean
Extender.compute_eq_spec
```

The constructor establishes the invariant, and each returned state preserves it for the next call. The fixed-size blob and cell types supply the byte lengths. `controls/downstream/KzgSmoke.lean` applies construction and execution without component premises.

## What a reader must trust

1. **Lean and dependencies.** Lean v4.29.1's kernel and only `propext`, `Classical.choice` and `Quot.sound`. `LeanBlsSimd/Axioms.lean` checks the imported BLS and KZG theorems, generated entry points and their transitive dependencies. `acceptedAxioms` is empty; `sorryAx`, `native_decide` and `bv_decide` dependencies are rejected. Aeneas's library can contain unrelated proof placeholders without those entering the checked closure. Using `lake exe cache get` additionally trusts downloaded Mathlib `.olean` artifacts, which Lean imports without rechecking their proofs; building Mathlib from source avoids that reliance.
2. **Specification and mathematics.** Mathlib v4.29.1 and [gattaca-com/EthLib at `5d7ab0f6`](https://github.com/gattaca-com/EthLib/tree/5d7ab0f648619d29da9637f8bd57b5e5aa093865) (`total-pairing-definitions`), including its field, group law, decoders, subgroup checks, KZG validation and cell-batch and `computeCells` specifications, and their fidelity to Ethereum's requirements. Agreement with vectors is finite evidence, not a proof of equivalence to other specifications or of the provenance of the embedded ceremony data. Manual review connects `G2Spec.verdict` to the private decoding stage of `coreVerify`: its fixed-size type supplies length 96, then it calls `G2.uncompress` and `G2.inSubgroup`. The stage accepts canonical infinity. Public-key validation, hash-to-curve and pairing in full signature verification are outside this proof.
3. **Input and output interpretation.** `ofArray`, `ofU8`, `ofBatch` and the affine conversions preserve bit-vectors, lanes and fields. Coordinates use six little-endian 64-bit Montgomery limbs with R = 2^384; G2 orders c0 before c1 and x before y. G1 and G2 public verdicts normalize through `toAffine`, including all-zero infinity. The G2 kernel conversion reads projective x/y; its bridge to the normalized verdict is proved for decoded finite points with z = 1. KZG's reduced scalar encoding uses four 64-bit Montgomery limbs with R = 2^256. The representation targets blst's 64-bit platform layout.
4. **Extraction and generated-code preparation.** Charon's MIR semantics, Aeneas's translation and the deterministic adaptations in `prepare-extraction.py` described in [reproduction](#reproducing-the-extraction). The pinned Aeneas revision is `d9733413`, Charon is `ed22146b`, and Charon uses nightly-2026-02-07 rather than the workspace's Rust 1.91.0. `extract.sh` verifies checkout pins and available binary version information; a Charon binary from another commit with the same reported crate version is not distinguished. The extraction targets x86_64, including its BLS chunk helpers, Fr FFT and verifier MSM8 kernels. The theorem includes the scalar route of this extraction; it does not check a separate non-x86_64 extraction. Transfer to other target configurations relies on their feature detection and source gating. Exact `--check` reproduction detects drift, not translator bugs.
5. **External semantics and bindings.** Aeneas's pinned Lean library models integers, arrays, slices, bounds/overflow checks, byte conversions and `partial_fixpoint` loops. `Extracted/TypesExternal.lean` and `FunsExternal.lean` bind the vector types, AVX-512 operations, SHA/SSE operations, carry arithmetic, lane extraction, feature detection and standard-library operations such as `Vec.clear`. These models specify bit patterns and logical contents; their agreement with hardware, ABI and standard-library behavior remains a trust boundary. Intrinsic controls check concrete cases and selected mutations. The opaque Rust functions below are replaced by hand; their source code is not refined by the extraction. The extraction contains the portable scalar, field, G1, MSM, pairing and SHA implementations themselves.
6. **CPU observations and G2 fallback.** `RuntimeFeatures` supplies independent SIMD, SHA and BMI2 Booleans, fixed for a theorem instance. Its mixed-state model does not establish hardware support for arbitrary stored routes; constructor-produced states align those routes with stable CPU observations. `BlsExternals` supplies only the deterministic total `uncompressG2` observation for the signature-decoding path. `UncompressG2.BlstMatchesSpec` requires exact agreement on every 96-byte input, including acceptance, affine limbs and infinity. The external wrapper returns `ok`, so termination and absence of Rust-level failure for that opaque call are assumed. KZG does not use this external. The blst structs retained in generated KZG types are data containers, not evidence of calls to blst operations.
7. **Generated-component contracts.** The two [KZG premises](#kzg-verifier), `PortableMsmCorrect` and `PairingCorrect`, are explicit propositions about actual generated definitions. `Portable.Fp.portable_fp_correct` and `Portable.Decode.g1_decoder_correct` prove the Fp and G1 contracts. These proofs, scalar arithmetic and bytes, and both SHA routes supply no headline premises. No contract is introduced as an axiom, and no whole-verifier or whole-challenge conclusion is hidden in a field. `ShaRep` has a fixed observational meaning. The portable table relation has a CPU-independent field interpretation, and its constructor is proved. Negative controls do not establish the pending MSM and pairing premises. The extender and both constructors have no component-contract premises.
8. **Runtime setup for literal-upstream corollaries.** Only `verify_eq_upstream` and `LeanBlsSimd.Kzg.model_eq_spec` require `TrustedSetup.get! = pure embeddedSetup`, including that no importer changes the public `TrustedSetup.globalRef`. The initialized reference and `ST.Prim.Ref.get` are opaque in Lean. The embedded-setup theorem instead uses the explicit value and the proved embedded-byte certificates.

Every `--opaque` item in `extract.sh` has this interpretation:

| Rust function | Handwritten interpretation |
|---|---|
| `bls::fp8::lanes` | Bitwise extraction of the eight vector lanes. |
| `ifma_available` | The fixed SIMD Boolean in `RuntimeFeatures`. |
| `sha_available` | The fixed SHA Boolean in `RuntimeFeatures`. |
| `bmi2_available` | The fixed BMI2 Boolean in `RuntimeFeatures`. |
| `bls::uncompress_in_g2_blst` | The signature decoder observation in `BlsExternals`; excluded from KZG. |
| `sha256::extensions::load_bytes` | Raw-pointer byte loads replaced by little-endian 32-bit lane packing. |
| `sha256::extensions::load_words` | Raw-pointer word loads replaced by 32-bit lane packing. |
| `sha256::extensions::store_words` | Raw-pointer word stores replaced by 32-bit lane unpacking. |

The three SHA load/store bindings replace Rust source routines, in addition to the intrinsic instruction models.


Compiled Rust additionally depends on the compiler, linking, ABI, CPU detection and hardware. The theorem describes Aeneas execution results; it does not prove absence of allocation failures or capacity panics, as detailed in the KZG runtime scope above. The extender has fixed buffer sizes, but its allocations still rely on the runtime and available memory.

## Reproducing the proof and checks

You need [elan](https://github.com/leanprover/elan). From `lean/`:

```sh
lake exe cache get
lake build
```

`lake exe cache get` fetches Mathlib's prebuilt files; run it from `lean/`. Lean imports those files without rechecking Mathlib's proofs. Building Mathlib from source avoids reliance on those prebuilt artifacts.

`lake build` compiles Aeneas's Lean library and the proof, then runs the axiom guard. Aeneas's library may print `declaration uses 'sorry'` warnings; the guard checks that none of the declarations it covers depend on those `sorry`s. The default build prints the library guard and the stricter control guard. Each reports its theorem count, generated entry-point inventory, and `axioms used: [propext, Quot.sound, Classical.choice]`. A cold build also compiles uncached dependencies and needs substantially more time than a rebuild.

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
python3 -I controls/sha-mutation-check.py
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

The differential executable exits 0 when every value matches, 1 on an output mismatch or an extracted computation returning `fail` or `div`, and 2 on invalid arguments or an unreadable, malformed or incomplete file. The Python entry point runs both `check_g1_controls.py` and `check_g2_controls.py`. They require those exit codes and diagnostics on valid small fixtures with permitted whitespace/comments, corrupted kernel/scalar/wrapper values, truncated input and out-of-range references. G2 also checks corruption of an undecided infinity verdict, missing wrapper cases, count mismatch, wrong limb count and trailing text. Building the executable for the first time can take several additional minutes.

From the repository root, fetch the KZG specification vectors and run the crate's Rust checks, including comparison with the c-kzg reference implementation:

```sh
make -C crates/crypto_simd
SILVER_REQUIRE_IFMA=1 cargo test --locked -p silver_crypto_simd --all-features
```

The IFMA requirement applies to the BLS and Fr FFT kernel checks on a supported x86_64 host. Lean jobs can use substantial memory; run one at a time. The default build and the controls must be rebuilt after changing an import before their results are used.

### Reproducing the extraction

`lean/extract.sh` reruns Charon and Aeneas on the `silver_crypto_simd` crate and compares the result with `lean/LeanBlsSimd/Extracted/Types.lean`, `Literals.lean` and `Funs.lean`. It needs `AENEAS_DIR`, a checkout of [Aeneas](https://github.com/AeneasVerif/aeneas) at the commit that `lean/lake-manifest.json` pins for `aeneas`. In that checkout, `make setup-charon` builds Charon at the commit in `charon-pin`, and `make` builds Aeneas. Charon also needs rustup, which installs its nightly. The script refuses to run if either checkout differs from its pin. It also checks the binaries: Aeneas reports the commit it was built from, but Charon reports only its crate version, so a Charon binary built from another commit with the same version would pass. From `lean/`:

```sh
AENEAS_DIR=/path/to/aeneas ./extract.sh --check
```

Aeneas records each item's origin in a `Source: '<file>', lines <span>` comment. The comparison ignores the line numbers in these comments and compares everything else exactly, including comment delimiters. A Rust edit that only moves these source locations therefore produces no reported drift. With `--check`, the script does not replace the generated files: it prints any other difference and exits 1, or exits 0 when there is none.

If the generated code has drifted, run `./extract.sh` without `--check`, which replaces `Types.lean`, `Literals.lean`, `Funs.lean` and `controls/ExtractedLiterals.lean`, and follow `lean/README.md`. Rebuild and fix the affected BLS or KZG refinements. Update the models and specification proofs where behaviour changes. Then rerun the controls, Lean differential tests and Rust checks, and update the BLS source table below when its files change. A passing vector test does not replace the drift check, since it covers only the recorded inputs.

The extraction roots are `crate::bls::decompress_g2::decompress`, `crate::bls::uncompress_in_g1`, `crate::bls::uncompress_in_g2`, `crate::kzg::verify` and `crate::kzg::cell_extender`. They reach both KZG types' public methods and `Default` implementations, IFMA kernels, `CurveWork`, streaming SHA and the portable arithmetic, decoder, MSM and pairing implementations. G2's `uncompress_in_g2_blst` remains opaque for signatures. `prepare-extraction.py` then:

- introduces a section with `RuntimeFeatures` and the G2-only `BlsExternals`; Lean retains a parameter only where a generated definition uses it;
- quotes the eight generated `full` identifiers;
- supplies structural `Array.make` length witnesses;
- recursively hoists G1 setup rows and pairing-table steps/lanes into the separate `Extracted/Literals.lean` module, preserving each literal's type, order and contents.

Both extraction modes retain raw `Funs.lean` in temporary storage and independently expand the prepared literals against it. Validation runs before comparison or replacement. The script also regenerates `controls/ExtractedLiterals.lean`: `--check` compares it, and default mode updates it.

The separate literal module prevents ordinary function edits from rebuilding the large tables. `controls/ExtractedLiterals.lean` checks equality with the unhoisted extracted literals. Preparation validates required entry points and literal structure. Extraction fixtures accept source-span changes and reject semantic drift, malformed literals and missing or duplicated entries.

All adaptations run before drift comparison. Only numeric source spans are masked; the rest of the generated files is compared exactly. Handwritten external files are preserved by regeneration. The explicit `portable.fp2.Fp2.new` helper is included in the fresh extraction so the nested pairing-table write contains the constructed Fp2 value.

### Project map

| Path under `lean/` | Content |
|---|---|
| `lean-toolchain`, `lakefile.toml`, `lake-manifest.json` | Lean and dependency pins: Lean v4.29.1, Mathlib v4.29.1, gattaca-com/EthLib at `5d7ab0f6` and Aeneas at `d973341320c1` (`backends/lean`). `lakefile.toml` also sets `autoImplicit` and `relaxedAutoImplicit` to `false`. The manifest records exact resolved revisions; `extract.sh` reads the Aeneas pin from it. |
| `LeanBlsSimd/Constants.lean` | p, r, z, R, and the Rust's constant tables proved equal to their derivations. |
| `LeanBlsSimd/Spec/` | G1 and G2 Scott soundness and completeness, point-count bounds, generator identities, field and group laws, square roots, G1 KZG encoding bridges, and both groups' affine-layout bridges. |
| `LeanBlsSimd/Extracted/` | The Lean code that Aeneas generates from the Rust, `Types.lean`, `Literals.lean` and `Funs.lean`, never edited by hand; and the hand-written external definitions in `TypesExternal.lean` and `FunsExternal.lean`. |
| `LeanBlsSimd/Model/` | The Rust, transcribed by hand: the proved intermediate step between the generated code and the specification. |
| `LeanBlsSimd/Proofs/` | The model against the specification, including G1's `DecompressG1.lean`, G2's `Kernel.lean` and the G2 wrapper verdict bridge in `UncompressG2.lean`. |
| `LeanBlsSimd/Refines/` | The generated code against the model, function by function, with public wrapper APIs in `UncompressG1.lean` and `UncompressG2.lean`, both length-mismatch theorems in `WrapperLengths.lean`, and G2's kernel headline in `Complete.lean`. |
| `LeanBlsSimd/Kzg/` | KZG specification decomposition, setup certificates, decoder bridge, representation laws, verifier refinements and public statements; `Extender/` contains the cell-extension model, refinements and specification bridge. |
| `LeanBlsSimd/Msm8/` | Generated verifier MSM refinements: GLV splitting, stores, buckets, affine batches, complete sums and output representation. |
| `LeanBlsSimd/Axioms.lean` | The common axiom guard for BLS and KZG. |
| `controls/` | BLS/KZG Lean controls, the common `AxiomLog.lean`, `KzgStrictAxioms.lean`, extraction fixtures in `extraction-check.py`, and the independent `downstream/` package. |
| `Test/Main.lean`, `Test/Differential/` | The differential CLI, shared parser and separate G1/G2 checks; the G1/G2 module docstrings describe the formats. |
| `Test/check_g1_controls.py`, `Test/check_g2_controls.py` | Positive formatting and negative value/parser controls for both differential runners; the G1 entry point runs both groups for CI. |
| `extract.sh` | Regenerates `LeanBlsSimd/Extracted/Types.lean`, `Literals.lean` and `Funs.lean`, or checks them for drift. |

## BLS proof internals

The proof has two parts: the generated code returns exactly the result of a hand-written model, and the model agrees with the specification on every lane the kernel decides. G2's Scott completeness uses a character-sum bound on the curve's point count; G1 uses the elementary finite point-count bound described below. Recorded test vectors also compare the generated code and model with the compiled Rust. Those tests check the translation on particular inputs; they are not a proof of the translation itself.

### Montgomery multiplication and squaring

`Proofs/EarlyCarry.lean` proves the wrapping carry identity under the inverse-modulus premise.
`Proofs/Reduction.lean` proves that each generated reduction row agrees with the reference model
on the limbs above its row index, then transports that agreement through all rows and final
carry extraction. The row's dead low limb is deliberately outside this equality.
`Proofs/Square.lean` equates the triangular square accumulator with the full product accumulator,
including wrapping additions. The Fp8 and Fr8 refinements use these identities to reuse the
existing arithmetic bounds and public contracts.

### Lazy field arithmetic and point formulas

Fp8 uses the same [range classes as the Fr8 FFT kernel](#ifma-fr-fft-kernel), with modulus `p` and eight radix-52 limbs:

| Class | Integer value | Limbs | Lean predicates |
|---|---|---|---|
| Normalized | In `[0, R)`, where `R = 2^416` | Each in `[0, 2^52)` | `SignedLimbs.Normalized` |
| Reduced | In `[0, 2p)` | Normalized | `Fp8Inv`; `Fp8.Holds` also records the field value |
| `Lazy k m` | In `[0, k*p)` | Signed magnitudes below `m*2^52` | `Fp8.Lazy`; `Fp8.LazyRep` also records the field value |
| Bounded | In `[0, k*p)` | Normalized | `Fp8.BoundRep` records the bound and field value |
| Offset | Exactly `c*p` | Normalized | `Fp8.Offset` |

The shared `SignedLimbs` model defines raw addition, offset subtraction and signed carrying for both fields.
Its width-generic normalization theorem preserves values in `[0, 2^(52*n))` when each limb has magnitude below `2^62`.
The five- and eight-limb theorems follow as corollaries.
`Refines/SignedLimbs.lean` shares the normalization, raw-addition and offset-subtraction refinements across both widths.
`Proofs/Fp8Lazy.lean` connects these operations to Montgomery field values and composes their bounds.
`Proofs/Fp8Holds.lean` supplies the reduced field representations shared by Fp8 and Fp2 proofs.
Conditional subtraction preserves residues when its offset is a multiple of `p`.
`Proofs/Fp8Multiple.lean` proves that `multiple_of_p c` returns normalized limbs for `c*p`, for every `c < 2^12`.

`mul_spec_of_product_lt` accepts normalized operands with product below `R*p` and proves a reduced result.
The existing multiplication theorems follow as special cases.
G1 formulas keep intermediate values below `10p`, with limb magnitudes below `6*2^52` before carrying.
Their largest product bound is `8p * 8p`, from squaring the doubled difference in point addition.
Offsets of `2p`, `4p` and `8p` keep differences nonnegative; final conditional subtractions restore reduced coordinates.
The G1 correctness theorems retain their reduced input and output contracts and their undecided-mask premises.

`Fp2x8.LazyRep` and `Fp2x8.BoundRep` apply the Fp8 classes to each component.
`BoundRep.mul` accepts normalized components below `16p`; its Karatsuba sums stay below `32p`.
The largest underlying Fp8 product is below `1024p²`, which is below `R*p`.
`BoundRep.square` accepts normalized components below `8p` and offsets the component difference by `8p`.
Its imaginary component uses `c0 * (2*c1)`, carrying the doubled operand before multiplying.
Both lemmas return reduced components; the existing reduced-input `Holds.mul` and `Holds.square` statements follow as corollaries.

G2's double and affine-add formulas use the same componentwise bounds as G1, with reduced coordinates at both boundaries.
Their multiplication operands stay below `16p`, and their square operands below `8p`.
G1 and G2 retain separate models of Rust's offset structs but share the Fp8 reduction-chain proofs.
The G2 formula theorems preserve their exact field triples and undecided-mask equalities.

### G1 Scott criterion

The Scott lemmas use σ(x, y) = (βx, y), with β fixed by the kernel's `BETA_MONT`, and the identity σ²(P) = [−z²]P. Completeness uses the spec's generator-order proof and the elementary bound `Nat.card E.Point ≤ 2 * p + 1 < r²`. Formula correctness is conditional on a clear undecided bit; the headline theorem does not require proving that subgroup members always avoid exceptional formulas.

### G2 wrapper refinement

The wrapper model uses SIMD availability, a threshold of three inputs per chunk, and padding that repeats the last input. `DecompressG2.decompress_lane_independent` proves that padding contents are unobservable in the public result. `UncompressG2.chunk_slice_refines` proves padding accesses stay in bounds and the generated padded chunk equals `chunkAt` exactly.

### G2 kernel proof and completeness

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

The supporting theorems that mention `decompress` refer to the model function and are stated in `lean/LeanBlsSimd/Proofs/Kernel.lean`. Through `decompress_refines`, they also apply to the generated `decompress`, with its result converted by `ofBatch`.

| Theorem | Statement |
|---|---|
| `valid_sound` | A `valid` lane decodes to a point of G2, and `points` holds it. It needs no Scott completeness, and `valid` implies the lane is decided. |
| `valid_complete` | Under `hC`, a decided lane that decodes to a point of G2 is `valid`. |
| `decode_lane` | On a decided lane, `on_curve` is set exactly when `G2.uncompress` succeeds. |
| `psi_generator` | ψ(G) = [z]G for the specification's generator G, in `Spec/Generator.lean`. |

`psi_generator` proves the Scott identity at G without assuming completeness. Its controls reject the opposite sign of z and two wrong ψ constants. `ScottCardinality.lean` and `CubicHasse.lean` extend this identity to every rational r-torsion point.

`Spec/ScottCardinality.lean` proves that G has exact order r, using the spec dependency's primality certificate for r. If r² does not divide the curve's point count, the quotient by G's cyclic subgroup has order coprime to r, so every rational r-torsion point is a multiple of G. The numerical Hasse interval `(p - 1)² ≤ Nat.card E'.Point ≤ (p + 1)²` contains no multiple of r²; both exclusions are checked in Lean's kernel.

`Spec/CubicHasse.lean` proves these Hasse bounds and concludes `scott_complete : ScottComplete`. `PointCount.lean` expresses the count as p² + 1 plus a quadratic-character sum. `CubeFiber.lean` and `CharacterSum.lean` express that sum as two weighted Jacobi sums, each with a coefficient of norm one. `JacobiNorm.lean` proves that a Jacobi sum has norm √q over a field of size q when both characters and their product are nontrivial. The character-order arguments and `cubic_mul_quadratic_ne_one` establish these conditions for both sums here. With q = p², the triangle inequality then gives the required bound of 2p. This proves the bounds for the existing twist; it does not compute its exact point count. The conditional cardinality and cyclicity APIs remain available.

### Vector evidence

Rerun the Lean check when its code, toolchain, dependencies or vector file changes.

`decompress_g1_vectors.txt` contains 47 batches (376 lanes), both masks and twelve limbs per kernel point, plus the scalar blst verdict on every lane. Cases include both signs, generator multiples, all five small cofactor prime orders, non-members, non-residues, x at and around p, all flag combinations and malformed infinity.

The same file records 24 wrapper cases in three families at lengths 0, 1, 7, 8, 9, 15, 16 and 17.

The G1 checks are:

- `g1::replay_vectors` runs the G1 replay check.
- `g1::recorded_matches_blst` checks the G1 recording against blst.
- `lake exe differential ../decompress_g2_vectors.txt --g1 ../decompress_g1_vectors.txt` compares the model, extraction and recorded blst verdicts. The G1 public theorem uses the proved actual portable decoder; recorded scalar results cannot be installed as its fallback. These finite comparisons supplement the universal decoder proof.

The pinned specification and blst 0.3.16 agree on canonical compressed infinity: `0xc0` followed by 47 zero bytes is accepted; other infinity encodings are rejected. `validateKzgG1` explicitly allows this encoding, and `G1.uncompress` returns `G1.zero`. blst's `POINTonE1_Uncompress_Z` zeroes the affine output for it, and `blst_p1_affine_in_g1` accepts it. The kernel marks compressed infinity lanes undecided, and the public G1 wrapper handles them through its portable decoder. The Lean infinity lemmas prove the specification verdict and kernel fallback behavior; the vector file separately records blst agreement.

`decompress_g2_vectors.txt` holds 105 batches of eight encodings, 840 lanes, with all three masks, every lane's `points` as `decompress` returned them, and a scalar blst verdict on every lane. The batches mix seeded cases from `src/bls/tests/g2_cases.rs`, the generator the crate's own tests use, with hand-picked edge cases: flag combinations, infinity encodings, coordinates at and around p in every word, x with no square root, points outside G2 and of small order, and both early returns, taken and not taken.

The same file records 39 G2 wrapper cases: member, mixed and rejected families at lengths 0, 1, 2, 3, 4, 7, 8, 9, 10, 11, 15, 16 and 17. Mixed cases include canonical infinity, malformed infinity and rejected encodings. These lengths exercise the threshold, full chunks and tails on both sides of the threshold.

The G2 checks are:

- `replay_vectors`, in `vectors.rs`, runs the current kernel and public wrapper on the recorded inputs and fails if any output differs. The wrapper starts with nonzero output sentinels. It runs with the crate's other tests. On x86_64 it skips when the `simd` feature or AVX-512F/IFMA support is unavailable; setting `SILVER_REQUIRE_IFMA` to any value makes that a failure. On other architectures this test target contains no tests, even with that variable set.
- `recorded_matches_blst`, also in `vectors.rs`, checks the recorded outputs against blst. It checks every recorded scalar verdict against `uncompress_in_g2_blst`, checks wrapper outputs against those verdicts, and compares acceptance and accepted kernel limbs on all 716 decided lanes. It uses recorded outputs instead of running the kernel, so it needs no IFMA and never skips on x86_64.
- `lake exe differential`, in `lean/Test/Main.lean`, runs the model and generated kernel on the same inputs through Lean's compiler. It also compares `G2Spec.verdict` with the recorded blst verdict on every input, including undecided and infinity lanes, and checks both SIMD settings of the model and generated wrapper with recorded scalar results as externals and nonzero output sentinels. It fails if any compared value differs. These finite checks do not prove `BlstMatchesSpec`. The runner reports kernel, spec/blst and wrapper times separately; they are test-run timings, not performance benchmarks.

When all three checks pass and `replay_vectors` has run rather than skipped, the Rust, model and generated code agree on every recorded batch. The specification agrees with blst on all recorded inputs, including canonical infinity (`0xc0` followed by 95 zero bytes), whose verdict is `some` of 24 zero limbs. The wrapper checks exercise the recorded cases, while the Lean theorem covers all lengths and inputs under its stated premise.

`replay_vectors` detects changes to the kernel's outputs on these inputs, including `points` on lanes the caller never reads. Unlike the source hashes below, it ignores changes to comments and formatting. The batches do not exercise every possible discrepancy: Scott's two coordinate comparisons, for example, always agree on them, so changing only one comparison can go undetected.

Format details live in `lean/Test/Differential/G1.lean`; G2's format lives in `G2.lean`.

`g1::write_vectors` is the ignored G1 generator.

When `replay_vectors` fails, `lean/README.md` explains what to do. To regenerate the files, run this from the silver repository root on an x86_64 host with AVX-512F and AVX-512 IFMA:

```sh
cargo test -p silver_crypto_simd --profile release-with-debug --test proof_vectors -- --ignored write_vectors
```

G2's `write_vectors` checks the mask expectations attached to each edge batch before writing the file. Some expectations constrain only selected lanes or masks. Both generators check acceptance and accepted points against blst on every lane the new kernel marks decided, leaving the file untouched if any check fails.

### BLS proof controls

Paths below are relative to `lean/controls/`. The common reproduction commands run these files alongside the KZG controls.

| File | Shows |
|---|---|
| `Guard.lean` | The axiom guard rejects `native_decide`, `bv_decide` and `Lean.ofReduceBool`. |
| `G1.lean` | Concrete G1 constants, routing flags, signs and limb order; skipping canonicality makes the kernel accept a noncanonical encoding of 2G. Also covers full chunks, scalar tails, empty output and arbitrary fallback. |
| `downstream/` | A separate Lake package transports both groups' list results across independently extracted structs, checks a generated-spelling caller with only downstream externals, and guards the root-name collision and proof axiom lists. |
| `G2Wrapper.lean` | Wrong SIMD routing, thresholds, ignoring undecided lanes and dropping accepted kernel results change observable verdicts (the accepted-result mutation is a compiled `#eval`). Tail controls distinguish scalar and kernel routing after a full chunk; reading the chunk's first input on fallback changes the verdict. Rejecting infinity, accepting malformed infinity or returning wrong affine limbs violates `BlstMatchesSpec`; unequal lengths fail. These controls do not claim to observe padding contents. |
| `G2Consumer.lean` | The public G2 list and model corollaries and length mismatch result can be applied from a separate module; a specification-backed external satisfies the universal premise at both SIMD settings. |
| `G1Consumer.lean` | A downstream module imports the G1 public theorem and applies it under the generated portable-decoder premise. |
| `Statements.lean` | Changed constants and formulas break their proof scripts, including G1's Scott-membership proof when the model drops the y negation. |
| `Limbs.lean`, `Fp8.lean`, `G2Group.lean`, `Decompress.lean` | A mutated constant, formula, carry or mask breaks the proof that uses it. `Limbs.lean` also shows that the early-carry model expression depends on its shift. |
| `EarlyCarry.lean` | Both modulus constants satisfy the carry identity; omitting or decreasing MASK52 and replacing the wrapping sum by a natural-number sum give concrete counterexamples. |
| `Square.lean` | The triangular square accumulator equals the full product; omitting cross-term doubling fails on an input with two nonzero limbs. |
| `Fp8Lazy.lean` | Missing conditional subtraction violates the reduced bound; an insufficient offset makes a difference negative; a tighter lazy bound fails. Normalized operands alone do not guarantee a reduced product. |
| `Fp2Lazy.lean` | Karatsuba sums need carrying; a smaller square offset makes a valid lazy difference negative. Omitting the imaginary-component doubling violates the square contract. |
| `G2Lazy.lean` | Dropping the final conditional subtraction leaves nonreduced components. Replacing the double formula's `8p` offset with `4p` makes a valid intermediate difference negative. |
| `Reduction.lean` | Both widths retain the stale dead limb; dropping the inverse premise can change a surviving limb. The valid inverse case agrees above the row index. |
| `Generator.lean` | −z, or a wrong ψ constant, breaks `psi_generator`. |
| `ScottCardinality.lean` | The generator's order is not r²; dropping either Hasse bound makes the numerical exclusion of multiples of r² false. |
| `CharacterSums.lean` | Scott soundness and completeness together; zero, cube and noncube fibers over F₇; the affine point count over F₅; and a counterexample to the Jacobi norm identity for trivial characters. |
| `Kernel.lean` | Checks the input premises and conclusions on concrete batches, including the generator's batch. These examples need no Scott completeness assumption, but do not prove completeness for arbitrary inputs. |
| `Refines.lean` | Mutated generated functions fail their refinement proofs, including G1's chunk fallback reading lane zero instead of the current lane. Concrete refutations cover five complete G2 refinements and the required loop steps for `times_minus_z` and G1's fallback. |
| `AxiomLog.lean` | Prints the axioms of every theorem. |

### Extracted BLS source

`lean/LeanBlsSimd/Extracted/Types.lean`, `Literals.lean` and `Funs.lean` contain items generated from the following Rust files. These content hashes inventory selected BLS sources, including shared arithmetic and the verifier MSM module. `extract.sh --check` verifies their correspondence with the generated files.

| File | sha256 | git blob |
|---|---|---|
| `mod.rs` | `e980912da65a7c55fc2d21af13928589e243f5bd44ec57f41d32533a5dc626d0` | `93a808f992ed56665b6602ad54a98e04bc072398` |
| `constants.rs` | `920097ea1f31efd78b3267a998fbef5e7bde79886203f8769b3338f0accb99df` | `a26bd1e4105a84d831b852086f29ece76292381c` |
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

G1 coverage includes `uncompress_in_g1`, `decompress_g1_chunk`, the decoder, group operations and shared arithmetic. G1 portable decoding is a generated-code contract; CPU observations remain external inputs. G2 coverage includes `uncompress_in_g2`, `decompress_g2_chunk`, the decoder, group operations and shared arithmetic. The G2 wrapper refinement proves the chunk routing, padding bounds, fallback calls and output writes. The correspondence to `coreVerify` is described in the consolidated trust list. The extraction also includes blst 0.3.16's field and affine structures from `src/bindings.rs`.

To check for changes since the proof, run this from `crates/crypto_simd/src/bls`:

```sh
sha256sum -c <<'EOF'
e980912da65a7c55fc2d21af13928589e243f5bd44ec57f41d32533a5dc626d0  mod.rs
920097ea1f31efd78b3267a998fbef5e7bde79886203f8769b3338f0accb99df  constants.rs
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
| `ShaContracts.lean`, `PortableFp.lean`, `PortableMsmContract.lean`, `PairingContract.lean` | Remaining named premises about generated components |
| `Contracts.lean` | Internal bundle of generated-component premises |
| `CurveWorkState.lean`, `PairingTable.lean`, `PairingTableBounds.lean`, `PairingTableConstruction.lean` | Exact table preservation, semantic invariant, literal certificates and generated constructor proof |
| `Model.lean` | Spec decomposition, column-aggregated IFFT and intermediate computations |
| `IOLawful.lean` | Monad laws missing from Lean v4.29.1's IO interface |
| `SpecBridge.lean` | Full-result correspondence between the pure model and upstream |
| `SetupArithmetic.lean`, `SetupPoints.lean` | Kernel-checked decoding and subgroup certificates for the embedded points |
| `Setup.lean` | Embedded-byte connection and persistent-state invariant |
| `PolynomialModel.lean`, `PolynomialArithmetic.lean`, `PolynomialInterpolation.lean` | Exact coefficient-array sizes and their polynomial interpretations |
| `CosetPolynomial.lean`, `ColumnPolynomial.lean`, `InterpolationIdentity.lean` | Coset IFFT correctness and weighted column interpolation |
| `ModelSpec.lean` | Input invariants and full-result spec equivalence |
| `Statements.lean` | Model/spec equivalence, interpolation, construction, refinement and headline theorems |
| `Refines.lean` | Supporting statements for decoding, challenge, roots, IFFT and pairing inputs |
| `Refines/` | Proofs for the extracted functions and shared loop lemmas |
| `InterpolationKernel/` | Canonical cell checks, weighted columns, the shared 64-point DIT, coefficient stores and kernel construction |
| `Lincomb.lean` | Actual `verify.CurveWork.sum`, ordinary scalar conversion, proved MSM8 and premised portable MSM |
| `Routes.lean` | Preservation of the interpolation option, curve-work route and stored table through successful calls |
| `Decoder.lean` | Direct composition with the shared BLS decoder proofs |
| `G1Bridge.lean` | Generic transport theorem for independent extractions; the shared verifier uses `Decoder.lean` |

`column_ifft_eq_interpolation` states T1 for aligned arrays, 64 field elements per cell and indices below 128. These are intermediate invariants established by the front half, not new assumptions on untrusted inputs. `spec_eq_column_ifft` states T2 for all spec inputs, preserving both the Boolean and errors as `KzgM` actions. `RliInputs` retains equality of the powers and index lengths: T1 could omit it, but the front half establishes it and the refinement uses aligned batches. The proofs establish index bounds and compression/decompression round trips explicitly; Lean's logical `get!` and panic fallback values do not certify that the executable avoids those branches.

The streaming challenge proofs accumulate the exact upstream transcript in both SHA paths, then use the proved reducing scalar decode. The inverse FFT proof covers the generated recursive transform and scaling. The aggregation, bit-reversed column copy and shift-add loops are proved separately; `InterpolationModel.lean` proves that their pure composition equals `columnRli`, including skipped zero columns. The interpolation commitment and pairing proofs compose these loops with the portable field/MSM and lane/portable pairing contracts. `ModelPairing.lean` proves the corresponding pure-model computation, including successful compression round trips and empty linear combinations. `glue_refinement` combines every generated verifier branch with that model and preserves the state invariant, under the named generated-component and slice-size premises. `InterpolationIdentity.lean` proves that the column IFFT equals the spec's per-cell interpolation. It interprets coefficient arrays as Mathlib polynomials, relates the spec interpolation loops to Lagrange interpolation, and proves the shifted IFFT has the same evaluations at all 64 distinct coset nodes. Interpolation linearity then regroups the weighted cells by column. Both arrays retain size 64, so polynomial injectivity recovers exact array equality, including trailing zero coefficients. `ModelSpec.lean` derives the intermediate shape contract from successful decoding and replaces the interpolation step while preserving the full `Except` result and arbitrary setup-loader actions. These proofs establish `column_ifft_eq_interpolation` (T1) and `spec_eq_column_ifft` (T2).

`SpecBridge.lean` proves `verifyWith_pure` for every setup, RLI step and input, preserving the complete `Except` result. `g1Lincomb_eq` connects the pure linear combination to upstream; `upstream_eq_verifyWith` composes the front and implementation decompositions used by the literal-upstream corollaries. `IOLawful.lean` proves `LawfulMonad (EST ε σ)` and derives the IO instance missing from Lean v4.29.1's interface.

### SHA-256 and challenge proof

`Sha256/Correct.lean` constructs `Sha256.sha_correct : Kzg.ShaCorrect` for the actual portable and SHA-extension constructors, updates and finishes. Challenge refinements use this theorem and the proved digest reduction internally; they take no hash contract premise.

Both implementations use one `Streaming.Represents` invariant: state words equal the specification compression fold over complete blocks, the first `pending_len < 64` bytes are the remaining suffix, and length is the absorbed byte count modulo 2^64. `Streaming.update_append` and `finish_eq_hash` are proved once. `Generated.lean` factors schedules definitionally equal to both generated update/finish bodies. Their shared refinements cover filling a pending block, direct block folds, remainder copies, one- or two-block padding and big-endian output. The accumulated message length is unrestricted. `ContractAdapter.lean` derives observational `ShaRep`; its continuation laws cover every state satisfying that relation.

The portable compressor proves byte loading, all 64 schedule words and rounds, feed-forward and the block fold. The extension compressor proves the ABEF/CDGH layout, four-round instruction and schedule-window steps, the generated inner loops and the block fold. The SHA/SSE models and three hand-replaced pointer routines belong to the documented extraction trust boundary.

### Extender proof structure

`Extender/Model.lean` decodes the blob and applies a 4096-point inverse FFT after input bit reversal. It multiplies coefficients by the first 4096 powers of the 8192nd root, then applies a forward FFT. It copies the original 64 cells and serializes the bit-reversed extension into the remaining 64 cells.

`SpecMath.lean` relates this transform to polynomial evaluation on both halves of the specification's domain. `Spec.lean` equates the complete `computeCells` action with the model, retaining errors; `SpecBytes.lean` proves serialization sizes and byte indexing. `Acceptance.lean` connects successful decoding to canonical big-endian field elements.

`Primitives.lean` proves construction from the shared roots refinement. `Decode.lean` proves decoding and early rejection, `Scale.lean` proves coefficient shifting, and `WriteStep.lean`, `WriteBytes.lean` and `Write.lean` prove every output byte and the first-half copy. `Refines.lean` composes the generated operations and preserves `Basic.lean`'s invariant; `Statements.lean` supplies the public results. The roots, scalar FFT and byte bridges use the proved scalar refinements without contract premises. Generated scalar zero, one, roots and inverse-size constants have independent kernel certificates. `Refines/InverseRoots.lean` shares the table-shape proof across 64, 4096 and 8192 entries and derives inverse entries from the root order. `SetupLiterals.lean` certifies the two test-only Rust G2 coordinate literals against `SetupPoints`; those literals are absent from production extraction. Run `python3 controls/setup-literals-check.py` from `proof/lean` to compare all 48 limbs with `src/kzg/setup.rs`. The checker also rejects a changed limb in each literal.

#### IFMA Fr FFT kernel

`Kernel/Basic.lean` relates each vector's eight lanes to field elements. Each lane's integer value reads its five limbs as signed 64-bit integers. The range classes match `fr8.rs`:

| Class | Integer value | Limbs |
|---|---|---|
| Normalized | Below `2^260` | Each in `[0, 2^52)` |
| Reduced (`Bounded`) | In `[0, 2r)` | Normalized |
| `Lazy k m` | In `[0, k*r)` | Each has magnitude below `m*2^52` |

`Model/SignedLimbs.lean` and `Proofs/SignedLimbs.lean` provide signed carry and raw arithmetic facts. `normalise` preserves the integer value when its limbs have magnitude below `2^62` and its value lies below `2^260`. `Refines/Fr8.lean` equates uncarried products with `Fr8.mulRaw`, using the [shared early-carry reduction proof](#montgomery-multiplication-and-squaring). `Reduction.rows_agree` transfers the surviving limbs to the reference accumulator. `Refines/Fr8Interleaving.lean` equates each combined row with independent reduction and product rows, including their wrapping additions. `Fr8.reduce_while_multiplying_eq` composes the rows into exactly `(reduce t, product a b)`. `Fr8.product_bound` bounds every unreduced accumulator limb below `2^56`, for arbitrary inputs. `Proofs/Fr8Product.lean` bounds the reduced product limbs below `2^57`. It bounds their value below `2r`, assuming normalized operands with `a*b < r*2^260`.

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

### Portable MSM components

`Portable/Msm/Buckets.lean` proves that portable bucket fill has the same generated schedule as the lane implementation after converting its five storage fields. `FillReady.lean` reuses the signed-digit, packing, weighted-sum and live-reference theorems. Its chunk bounds use the generated `CHUNK = 4096` constant.

`Store.Holds` describes canonical coordinates at an initialized slot without constraining reserved scratch. The store refinements prove signed references, writes and their frame property, allocation and reset. `BatchReject.lean` proves the generated equal-x branch returns false before inversion and preserves the store, including the first-job case for arbitrary scratch. `BatchFinish.lean` proves the affine finish formula and reuses the shared nonsingular addition theorem.

`BatchPrepare.lean` and `BatchUnwind.lean` refine each generated step using the shared four-chain product invariant and the proved portable batch inversion. The reverse step recovers each inverse and updates its chain accumulator. `BatchPrepareLoop.lean` composes preparation up to any nonzero prefix, proves later equal-x rejection through scratch resizing, and connects complete preparation to the generated reverse loop.

`BatchExecute.lean` composes the reverse loop under `ExecutionState` and `ReverseIndependent`, permitting a job to overwrite its own input while preserving earlier jobs. `BatchRun.lean` proves `Batch.run_cases`, deriving both rejection and execution for arbitrary scratch, without a successful-batch premise. `PortableMsmCorrect` remains an explicit verifier premise until the queue, round, fallback and chunk proofs are composed.

### Verifier MSM8 kernel

`lean/LeanBlsSimd/Msm8/` proves the verifier's eight-lane G1 linear combination. It is a verifier internal, alongside the interpolation kernel. The extender uses the shared Fr FFT proofs but does not call MSM8.

The refinements cover generated word arithmetic, scalar conversion, point stores, signed digits, buckets, affine batches and complete projective sums. They establish successful `Result` execution under internal representation and size invariants. The group proofs connect these results to the specification's weighted sum.

`PlainWords.lean` converts reduced blst scalars to ordinary little-endian words, preserving their values and length. Multiplication by 16 cancels blst's Montgomery factor `2^256` through the Fr kernel's factor `2^260`. Finite filtering removes paired infinity inputs without changing the sum. `G1AffineValid` supplies subgroup validity; reduced scalar encodings supply values below `2^255`.

`Glv.lean` checks the generated constants and carry arithmetic against `Model/Glv.lean`. The constants satisfy `λ = z² − 1` and `r = λ² + λ + 1`. The model uses the exact fixed-point reciprocal `Z2_OVER_R` and threshold `HALF_R_UP`. For every `0 ≤ k < 2^255`, the signed outputs satisfy `k₁ + λ*k₂ ≡ k (mod r)` and `|k₁|, |k₂| < 2^127`. `GlvGroup.lean` proves `σ(P) = [λ]P` for subgroup points, using the existing Scott completeness theorem. The split therefore preserves each point's scalar contribution.

`Store*.lean`, `Conversion.lean` and `AffineInput.lean` connect generated loads and writes to represented points. Point `i` occupies rows `2*i` and `2*i+1`, holding its x and y coordinates as eight radix-`2^52` words. Conversion changes the coordinate Montgomery factor from blst's `2^384` to Fp8's `2^416`. The proof checks the literal `TWO_POW_448_MOD_P = 2^448 mod p`. The first `n` entries hold signed original points; the next `n` hold signed endomorphism images. A reference uses its low 31 bits as the point index and bit 31 as a negation flag. Stores write lanes in order, so repeated indices retain the last write. Padding repeats the final job and preserves its result.

`SignedDigits.lean`, `Buckets.lean` and `Fill.lean` prove the generated signed-digit trace and exact ordered bucket contents. The selected widths are 4, 6 and 8 bits, with 32, 22 and 16 windows respectively. These windows cover the carry above a 127-bit half. A digit exactly at the half-window threshold remains positive. Queue reductions preserve each bucket's group sum while allocating or reusing independent output slots.

Affine batches accumulate nonzero x-coordinate differences into inversion chains. `Inversion.lean` proves that the generated exponent chain, including its final multiplication, computes exponent `p−2`. Batch invariants establish nonzero factors before inversion and justify unwinding the product. Equal x-coordinates reject a batch before inversion. The caller refills the original buckets and sums them using complete projective additions. Those additions cover infinity, doubling and cancellation.

`WindowSum.lean`, `Flatten.lean` and `Lanes.lean` recover the bucket and window weights. Bucket `b` contributes weight `b+1`; window `j` contributes `2^(bits*j)`. `Refines.lean` composes the generated chunk loop without an input-length bound. `OutputBridge.lean` connects the resulting lane to the generated `lane_zero_in_blst` conversion and the specification's `G1.msm`. Its conclusion is `G1Rep`, preserving infinity and affine coordinates without requiring identical Jacobian representatives.

`Bounds.lean` proves the counter bounds for a nonempty chunk with `n ≤ 2^24` finite points. There are at most `2*n` references per bucket and `2*n*windows` references overall. The store reserves `2*n + n*windows` points. The requested doubled row count fits 32 bits; allocated indices and the sentinel fit below the sign bit. Padding adds at most 15 entries. These are internal chunk bounds, not an additional public input-length premise.

The generated outer MSM loop processes chunks of at most `CHUNK = 4096` inputs. It combines their results with complete G1x8 additions. The constant satisfies `CHUNK ≤ 2^24`, establishing the finite-point bounds used by `Bounds.lean`. Group-sum composition covers every representable aligned input length; the public theorem adds no chunk-size premise. Empty inputs and chunks containing only infinity points contribute the identity. Chunking does not introduce a blst fallback.

### Field and point representations

`frEncode` uses four little-endian 64-bit limbs for the reduced Montgomery residue `x * 2^256 mod r`. Scalar laws apply to this encoding, not arbitrary limb arrays. The extraction and representation target blst's 64-bit platform layout, `limb_t = u64`; they do not describe a 32-bit-limb build.

`G1Rep` relates a Jacobian result to the spec by its infinity status and affine coordinates. It does not require blst and the spec to choose the same Jacobian representative. Affine coordinates use six reduced Montgomery limbs with `R = 2^384`. The pairing contract calls the spec's `pairingCheck`; both implementations omit pairs with either a G1 or a G2 point at infinity. `Sha256.sha_correct` proves both streaming implementations agree with specification SHA-256, and challenge refinement reaches `Fr.hashToBlsField` through reducing scalar decoding. The proved canonical scalar decode rejects integers greater than or equal to `r`. Portable G1 adapters retain the representation and validity conditions needed at their call sites. `G1Valid` checks subgroup membership on the Jacobian representative. `G1Validity.lean` transports this predicate through `G1Rep`, including arbitrary infinity representatives such as blst's all-zero triple, and proves that valid points have valid affine encodings. `G1Arithmetic.lean` proves closure and point equivalence for addition, negation, doubling and scalar multiplication under the same validity predicate. `G1Msm.lean` extends these results to multi-scalar multiplication, using upstream's weighted-sum theorem after normalizing infinity inputs. `G1Compression.lean` proves successful decompression after compression of a valid point, preserving infinity status and affine coordinates. Its header-bit certificate uses kernel reduction over 32 values. `PairingRepresentation.lean` transports the pairing inputs across these representative changes.

### Manual blst Fr audit

The v0.3.16 source audit covered Fr arithmetic and input-conversion wrappers in `blst/src/exports.c`. It also covered the final conditional subtraction in `blst/src/no_asm.h::mul_mont_n` and `add_mod_n`. The corresponding x86-64 ADX assembly and `blst/src/recip.c::reciprocal_fr` were checked. Addition, subtraction and Montgomery multiplication preserve reduction on reduced inputs. `blst_fr_from_scalar` also handles a full 256-bit SHA-256 digest: its other operand is the reduced Montgomery conversion constant, so the product is below `r * 2^256`. This historical audit is background for the former blst boundary. It is not a formal proof of blst and does not discharge the generated portable scalar contracts.

### Setup connection

`embeddedSetup` is the pinned spec's private `TrustedSetup.buildEmbedded` value, accessed with Batteries' `open private`. `embedded_setup_matches` proves equality of the 64 G1 compressed encodings used by the verifier, successful G2 decodes at indices 0 and 64, subgroup membership and successful G1 validation.

The proof compares the G1 Rust constants with the pinned specification and retains independent certificates for its two fixed G2 points. Generated KZG setup stores the G1 vector; the fixed pairing table supplies its G2-dependent data. `SetupPoints.lean` checks explicit witnesses for all 64 G1 points and both G2 points. Structural exponentiation and scalar multiplication reduce in the kernel, with general lemmas relating them to the spec operations. The certificate uses only the three standard axioms and needs no separate setup-file assumption. Relating the pinned spec's data to Ethereum's intended ceremony remains part of trusting the specification.

### Specification target and evidence

Ethereum's KZG specification lives in `ethereum/EthLib`, formerly `ethereum/cryptography-specs`. The proof pins the `gattaca-com/EthLib` fork on `total-pairing-definitions`: upstream `d1331f02`, the repository rename and CI changes, then total powers and a structurally recursive Miller loop. The package is `EthLib`; its cryptography modules use `EthLib.Cryptography`. Lean and Mathlib remain at v4.29.1. [Consensus-specs PR #5398, “Remove specs for KZG functions”](https://github.com/ethereum/consensus-specs/pull/5398), merged on 2026-07-29, removed those specifications from consensus-specs. Its stated intent is to keep them solely in that repository. [Fulu's `das-core.md` at v1.7.0-beta.4](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/fulu/das-core.md) links there. The v1.7.0-beta.4 `general.tar.gz` contains no KZG vectors.

[Consensus-spec-tests v1.6.0](https://github.com/ethereum/consensus-spec-tests/releases/tag/v1.6.0) provides KZG vectors generated by the earlier Python spec, before their removal from consensus-specs. Comparing its `general.tar.gz` with EthLib's `tests/kzg` at the pinned revision gives identical cases across all 12 suites after normalizing YAML text whitespace and letter case. This includes all 32 `verify_cell_kzg_proof_batch` cases and all 11 `compute_cells` cases. Agreement on these finite cases is checked; general equivalence to the Python spec is not proved.

EthLib generates its vectors by executing the compiled Lean spec and writing the Lean result. Its [`bindings/python/kzg.c`](https://github.com/gattaca-com/EthLib/blob/5d7ab0f648619d29da9637f8bd57b5e5aa093865/bindings/python/kzg.c) calls the Lean functions; the Lean spec has no `implemented_by` or `extern` overrides. Thus tests against those vectors check the implementation against the same Lean target. The c-kzg differential tests in [`src/kzg/tests.rs`](../src/kzg/tests.rs) provide further evidence from another implementation.

### Evidence and controls

The Rust [`spec_vectors.rs`](../src/kzg/spec_vectors.rs) tests the pinned `verify_cell_kzg_proof_batch`, challenge and `compute_cells` vectors. [`tests.rs`](../src/kzg/tests.rs) compares with the c-kzg reference implementation. These finite cases exercise the implementation against independent recorded or reference results; they do not discharge the universal generated-component premises. `compute_cells` checks exercise `CellExtender` against the same pinned specification as its proof.

The KZG source has no separate hash table. `extract.sh --check` checks all generated types, literals and functions, including KZG, using the comparison boundary above. The BLS hash table is an additional source inventory.

Paths below are relative to `lean/controls/`.

| Control | Checked boundary |
|---|---|
| `ContractSamples.lean` | Interpreter samples of generated Fr/byte operations, both portable Fp paths and both SHA implementations, with wrong-result controls. |
| `MsmSamples.lean` | Interpreter samples of actual portable MSM with reused scratch, infinity, cancellation and a wrong-weight control. |
| `PortableMsm.lean` | Generated signed-reference loads reject an omitted negation; writes preserve other slots. Equal-x jobs at the first or a later position reject a successful-round result without changing the store. The fifth preparation job checks reuse of the first chain and rejects an omitted prefix update. A complete batch permits overwriting its own input and rejects an omitted reverse write. Bucket counting rejects a dropped increment, and chunk counter bounds are checked. |
| `PairingSamples.lean` | Interpreter samples of portable pairing against the spec, including a nonzero true setup relation and its rejected sign mutation. |
| `KzgPairingTable.lean` | A changed first coefficient violates the semantic table invariant; changed scratch with the same table is accepted. |
| `KzgRuntimeBoundary.lean` | KZG headline and runtime dependency closures exclude the opaque G2 decoder; the signature-path control still reaches it. |
| `ShaGenerated.lean` | Generated updates reject a dropped length wrap; finish rejects a missing padding marker and reversed digest bytes. The proved `ShaCorrect` is checked with no premise. |
| `ShaExtensions.lean` | The ABEF/CDGH packing definitions differ on the fixture. Instruction samples distinguish an omitted shuffle, reused message words and omitted byte swapping. |
| `ShaPortable.lean` | Generated byte loading, schedule expansion and rounds reject reversed byte order, the wrong sigma function and a zeroed round constant. |
| `ShaStreaming.lean` | The shared streaming invariant excludes missing pending bytes and incorrect stored lengths; empty and split updates preserve the state. |
| `ShaSpec.lean` | Local fixtures distinguish round constants and feed-forward. Padding equations check the 55/56-byte boundary and bit-length wrap; a UInt64 fixture checks byte-count wrapping. |
| `sha-mutation-check.py` | Copies `Spec/Sha256.lean` and changes the round operand from `d+t1` to `c+t1`. Requires an unsolved goal in `compressBlock_eq`; timeouts fail the harness. Unchanged and reformatted sources must compile. |
| `KzgStreamingSha.lean` | Constant-zero hashing is rejected; changing chunk boundaries preserves the observed digest, and both proved generated SHA paths agree. |
| `ExtractedLiterals.lean`, `ShaIntrinsics.lean` | Hoisted literals equal the extracted values; SHA/SSE intrinsic fixtures and mutations check packing, lane order and round operands. |
| `PortableFpWords.lean` | Generated carry, subtraction and wide-product boundary witnesses retain the carry, borrow and high word. |
| `PortableG1Pair.lean` | Equal-point addition flags only the affected lane. One flagged lane is recomputed by the scalar test while the unflagged lane uses its chain; omitting that fallback rejects the generator. |
| `PortableDecode.lean` | Generated scalar decoding accepts canonical infinity, rejects a nonzero infinity tail and x = 0, enforces x < p, and retains a canonical nonzero x. Paired decoding preserves the order of an accepted infinity and a rejected zero-x encoding. |
| `PortableG1.lean` | Generated doubling preserves infinity; complete projective and affine addition handle opposite points. The scalar Scott test accepts the generator and rejects a false result. |
| `PortableFpInverse.lean` | Halving retains the incoming high bit; odd coefficients require the modulus correction; the one test checks upper words. Inversion covers zero and one and changes two. A zero factor in the four-element batch yields four zero outputs; four ones remain ones. |
| `PortableFpWide.lean` | Wide products retain the seventh word and last row. Subtraction retains borrow correction and rejects ordered underflow; reduction excludes a noncanonical modulus result. |
| `PortableFpPowers.lean` | Conversion removes the Montgomery scale; sign tests distinguish 1 and −1; zero roots succeed and the pair result retains both validity bits. |
| `PortableFpCorrect.lean` | Canonical wraparound and both BMI2 wrappers preserve Montgomery encoding; plain-one products and noncanonical modulus representatives are rejected. |
| `PortableFpReduction.lean` | Generated reduction maps the modulus to zero; the split product retains a high word shifted across the six-word boundary. |
| `FrScalar.lean` | Generated scalar refinements exclude dropped carries, missing borrows, a lost fifth word, incorrect reduction and wrong Montgomery encodings. |
| `FrBytes.lean` | Canonical decoding rejects r; digest reduction accepts the maximal 256-bit value. Generated decoding and serialization exclude reversed bytes. |
| `InverseRoots.lean` | The generated inverse table excludes forward ordering; the root-order proof rejects a wrong inverse exponent. |
| `SetupLiterals.lean` | The certified G2 literal excludes the wrong generator sign. |
| `setup-literals-check.py` | Both extraction modes require all 48 test-only Rust G2 limbs to match their Lean transcription; each literal rejects a single-limb mutation. |
| `KzgMathematical.lean` | Bit reversal, inverse coset-shift direction and inverse FFT scaling. |
| `KzgSetupBoundary.lean` | Replacing embedded G2 point 64 with infinity violates the setup match. |
| `InterpolationKernel.lean` | Wrong inverse-size shift factors or used-column flags violate the generated contracts. Unnormalized first products violate bounded DIT input. Noncanonical cells are rejected. Canonical acceptance and normalization supply positive controls. |
| `Msm8.lean` | Wrong bucket indices, digit signs, GLV constants and window weights violate their laws. Skipping equal-x rejection or the inverse chain's final multiplication fails concrete controls. Queue aliasing, allocation, repeated-job padding and scalar-word length have positive and negative cases. |
| `ExtenderMathematical.lean` | Extender input/output bit reversal, coset shifting, forward FFT direction and inverse FFT scaling at the blob size. |
| `ExtenderLayout.lean` | First-half copying, the extension's cell-64 offset, rejection of noncanonical blobs and output preservation on rejection; generated decoding rejects an all-`ff` blob. |
| `ExtenderKernelBoundary.lean` | The generated range mask rejects exact raw out-of-range values; permutation uses bit 3 and ignores higher bits; multiplier construction requires its factor of 16. Kernel byte encoding and portable scalar serialization are both proved. |
| `ExtenderKernelBytes.lean` | Omitting arithmetic reduction or output canonicalization, reversing byte order, omitting the cell-64 offset, and clearing the preserved first half each violate the generated contracts. |
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
| `KzgStrictAxioms.lean` | The shared proof, conditional runtime consumers and KZG negative controls use only the three standard axioms. |
| `KzgSetupAxioms.lean`, `KzgRefinementAxioms.lean`, `KzgRepresentationAxioms.lean`, `KzgSpecBridgeAxioms.lean`, `KzgPolynomialAxioms.lean` | Scoped axiom checks for setup, refinement, representations, spec bridge and interpolation. |
| `extraction-check.py` | Unchanged output, interleaved function families and numeric source-span changes pass. Changed rows, lanes, step order, helper types or attributes, malformed literals, a wrong `full` count, body edits and missing or duplicated entry points are rejected. Both extraction modes enforce raw expansion equality; default extraction updates all three generated files and the Lean equality control. |

For layer-specific build commands, see the [KZG scoped checks](lean/README.md#scoped-checks).

`Spec/PairingEquations.lean` proves unfolding equations for the total `Fp2.powNat`, `Fp12.powNat`, `millerSteps`, `millerLoop` and final exponentiation, and expresses `pairingCheck` as an array fold. `controls/PairingEquations.lean` prints their axioms.

The extender's mathematical controls distinguish the actual 4096-element transform stages using field-array witnesses. Its layout controls compare the generated copy loop and output-update function, plus mutations of the model's error branches. A further control constructs an extender and proves its generated decoder rejects an all-`ff` blob. They do not rerun a mutated Rust implementation.
