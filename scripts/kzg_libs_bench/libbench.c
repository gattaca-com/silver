// blst vs mcl (AVX-512 IFMA) on the operations that dominate
// verify_cell_kzg_proof_batch: per-proof subgroup checks and the two MSMs over
// the proofs. N = 1152 = 64 columns x 18 blobs.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MCLBN_FP_UNIT_SIZE 6
#define MCLBN_FR_UNIT_SIZE 4
#include <mcl/bn.h>

#include "blst.h"

#define N 1152
#define REPS 5

void proto_in_g1_16(const void *pts, size_t n, int *match_sigma1, int *match_sigma2);
int proto_sqrt_16(const void *xs, size_t n, void *ys);

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

#define BEST(var, body)                                   \
    do {                                                  \
        var = 1e30;                                       \
        for (int rep = 0; rep < REPS; rep++) {            \
            double t0 = now_ms();                         \
            body;                                         \
            double t = now_ms() - t0;                     \
            if (t < var) var = t;                         \
        }                                                 \
    } while (0)

static uint8_t compressed[N][48];
static mclBnG1 mcl_pts[N], mcl_pts2[N];
static mclBnFr mcl_sc255[N], mcl_sc128[N], mcl_zz[N];
static blst_p1_affine blst_pts[N];
static blst_scalar blst_sc255[N], blst_sc128[N];

static void blst_msm(blst_p1 *out, const blst_scalar *sc, size_t nbits) {
    static uint64_t scratch[1 << 20];
    const blst_p1_affine *pp[2] = {blst_pts, NULL};
    const uint8_t *sp[2] = {(const uint8_t *)sc, NULL};
    if (blst_p1s_mult_pippenger_scratch_sizeof(N) > sizeof scratch) abort();
    blst_p1s_mult_pippenger(out, pp, N, sp, nbits, scratch);
}

int main(void) {
    if (mclBn_init(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR) != 0) {
        puts("mcl init failed");
        return 1;
    }
    mclBn_setETHserialization(1);
    mclBn_verifyOrderG1(0);

    // Random G1 points, serialised in the compressed wire format both libraries read.
    for (int i = 0; i < N; i++) {
        char msg[32];
        snprintf(msg, sizeof msg, "proof-%d", i);
        mclBnG1_hashAndMapTo(&mcl_pts[i], msg, strlen(msg));
        if (mclBnG1_serialize(compressed[i], 48, &mcl_pts[i]) != 48) abort();
        if (blst_p1_uncompress(&blst_pts[i], compressed[i]) != BLST_SUCCESS) abort();
        mclBnFr_setByCSPRNG(&mcl_sc255[i]);
        uint8_t le[32];
        memset(le, 0, 32); if (mclBnFr_getLittleEndian(le, 32, &mcl_sc255[i]) == 0) abort();
        memcpy(&blst_sc255[i], le, 32);
        memset(le + 16, 0, 16);
        mclBnFr_setLittleEndian(&mcl_sc128[i], le, 16);
        memcpy(&blst_sc128[i], le, 32);
    }
    // z^2 for the Scott-style membership test [z^2]P vs sigma^2(P); z = -0xd201000000010000.
    // z^2 = 0xa8d4d05a0c1e4a0f... keep it as a 128-bit scalar built from z*z.
    {
        mclBnFr z;
        uint8_t zb[8] = {0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xd2};
        mclBnFr_setLittleEndian(&z, zb, 8);
        mclBnFr_mul(&mcl_zz[0], &z, &z);
        for (int i = 1; i < N; i++) mcl_zz[i] = mcl_zz[0];
    }

    double t_uncompress, t_in_g1, t_mcl_deser, t_mcl_order, t_mcl_each, t_mcl_each_255;
    double t_blst_msm255, t_blst_msm128, t_mcl_msm255, t_mcl_msm128;
    volatile int sink = 0;

    BEST(t_uncompress, {
        for (int i = 0; i < N; i++) {
            blst_p1_affine a;
            sink += blst_p1_uncompress(&a, compressed[i]);
        }
    });
    BEST(t_in_g1, {
        for (int i = 0; i < N; i++) sink += blst_p1_affine_in_g1(&blst_pts[i]);
    });
    BEST(t_mcl_deser, {
        for (int i = 0; i < N; i++) sink += (int)mclBnG1_deserialize(&mcl_pts2[i], compressed[i], 48);
    });
    BEST(t_mcl_order, {
        for (int i = 0; i < N; i++) sink += mclBnG1_isValidOrder(&mcl_pts[i]);
    });
    BEST(t_mcl_each, {
        memcpy(mcl_pts2, mcl_pts, sizeof mcl_pts);
        mclBnG1_mulEach(mcl_pts2, mcl_zz, N);
    });
    BEST(t_mcl_each_255, {
        memcpy(mcl_pts2, mcl_pts, sizeof mcl_pts);
        mclBnG1_mulEach(mcl_pts2, mcl_sc255, N);
    });

    blst_p1 out;
    mclBnG1 mout;
    BEST(t_blst_msm255, blst_msm(&out, blst_sc255, 255));
    BEST(t_blst_msm128, blst_msm(&out, blst_sc128, 128));
    BEST(t_mcl_msm255, { memcpy(mcl_pts2, mcl_pts, sizeof mcl_pts); mclBnG1_mulVec(&mout, mcl_pts2, mcl_sc255, N); });
    BEST(t_mcl_msm128, { memcpy(mcl_pts2, mcl_pts, sizeof mcl_pts); mclBnG1_mulVec(&mout, mcl_pts2, mcl_sc128, N); });

    // Cross-check: blst and mcl agree on the 255-bit MSM.
    {
        blst_p1_affine a;
        uint8_t bb[48], mb[48];
        blst_p1_to_affine(&a, &out);
        blst_msm(&out, blst_sc255, 255);
        blst_p1_compress(bb, &out);
        memcpy(mcl_pts2, mcl_pts, sizeof mcl_pts);
        mclBnG1_mulVec(&mout, mcl_pts2, mcl_sc255, N);
        mclBnG1_serialize(mb, 48, &mout);
        printf("msm cross-check: %s\n", memcmp(bb, mb, 48) == 0 ? "identical" : "DIFFER");
    }

    // Scalar field-op references: what one Fp mul and one sqrt cost on this core.
    double t_fp_mul, t_fp_sqrt;
    {
        blst_fp a = blst_pts[0].x, b = blst_pts[1].x, c;
        BEST(t_fp_mul, {
            for (int i = 0; i < 100000; i++) { blst_fp_mul(&c, &a, &b); a = c; }
        });
        BEST(t_fp_sqrt, {
            for (int i = 0; i < 1000; i++) { sink += blst_fp_sqrt(&c, &blst_pts[i].x); }
        });
    }
    printf("blst_fp_mul: %.1f ns; blst_fp_sqrt: %.2f us\n", t_fp_mul * 1e6 / 100000, t_fp_sqrt * 1e3 / 1000);

    // 16-way prototypes on mcl's IFMA types.
    static mclBnFp rhs[N], roots[N];
    for (int i = 0; i < N; i++) {
        mclBnG1_normalize(&mcl_pts[i], &mcl_pts[i]);
        mclBnFp t, four;
        mclBnFp_sqr(&t, &mcl_pts[i].x);
        mclBnFp_mul(&t, &t, &mcl_pts[i].x);
        mclBnFp_setInt32(&four, 4);
        mclBnFp_add(&rhs[i], &t, &four);
    }
    int m1 = 0, m2 = 0, ok = 0;
    double t_proto_g1, t_proto_sqrt;
    BEST(t_proto_g1, proto_in_g1_16(mcl_pts, N, &m1, &m2));
    BEST(t_proto_sqrt, ok = proto_sqrt_16(rhs, N, roots));
    printf("%-44s %8.2f ms  %6.2f us/pt  (sigma matches %d, sigma^2 matches %d of %d)\n",
           "proto in_g1 16-way [-z^2]P == sigma^k(P)", t_proto_g1, t_proto_g1 * 1e3 / N, m1, m2, N);
    printf("%-44s %8.2f ms  %6.2f us/pt  (%d of %d roots verified)\n", "proto sqrt 16-way x^((p+1)/4)",
           t_proto_sqrt, t_proto_sqrt * 1e3 / N, ok, N);

    printf("N = %d points\n", N);
    printf("%-44s %8.2f ms  %6.2f us/pt\n", "blst uncompress", t_uncompress, t_uncompress * 1e3 / N);
    printf("%-44s %8.2f ms  %6.2f us/pt\n", "blst in_g1 (Scott, 2 z-mults)", t_in_g1, t_in_g1 * 1e3 / N);
    printf("%-44s %8.2f ms  %6.2f us/pt\n", "mcl deserialize (no order check)", t_mcl_deser, t_mcl_deser * 1e3 / N);
    printf("%-44s %8.2f ms  %6.2f us/pt\n", "mcl isValidOrder (scalar)", t_mcl_order, t_mcl_order * 1e3 / N);
    printf("%-44s %8.2f ms  %6.2f us/pt\n", "mcl mulEach [z^2]P (AVX-512 16-way, GLV)", t_mcl_each, t_mcl_each * 1e3 / N);
    printf("%-44s %8.2f ms  %6.2f us/pt\n", "mcl mulEach 255-bit (AVX-512 16-way)", t_mcl_each_255, t_mcl_each_255 * 1e3 / N);
    printf("%-44s %8.2f ms  %6.2f us/pt\n", "blst pippenger 255-bit", t_blst_msm255, t_blst_msm255 * 1e3 / N);
    printf("%-44s %8.2f ms  %6.2f us/pt\n", "blst pippenger 128-bit", t_blst_msm128, t_blst_msm128 * 1e3 / N);
    printf("%-44s %8.2f ms  %6.2f us/pt\n", "mcl mulVec 255-bit (AVX-512 IFMA)", t_mcl_msm255, t_mcl_msm255 * 1e3 / N);
    printf("%-44s %8.2f ms  %6.2f us/pt\n", "mcl mulVec 128-bit (AVX-512 IFMA)", t_mcl_msm128, t_mcl_msm128 * 1e3 / N);
    return sink == 12345;
}
