
// ---- appended prototype: 16-way G1 membership test and Fp sqrt on mcl's AVX-512 IFMA types ----
namespace {

// R = [z]P, z = 0xd201000000010000 (bits 63,62,60,57,48,16), Jacobian coordinates.
template<bool mixed>
inline void mulZ(EcMA& R, const EcMA& P)
{
	R = P;
	for (int i = 62; i >= 0; i--) {
		EcMA::dbl<false>(R, R);
		if (i == 62 || i == 60 || i == 57 || i == 48 || i == 16) {
			EcMA::add<false, mixed>(R, R, P);
		}
	}
}

inline int popcnt16(const VmaskA& m)
{
	return __builtin_popcount(m.v[0]) + __builtin_popcount(m.v[1]);
}

// (p + 1) / 4, little-endian 64-bit limbs; 379 bits.
const uint64_t g_sqrtExp[6] = {
	0xee7fbfffffffeaabULL, 0x07aaffffac54ffffULL, 0xd9cc34a83dac3d89ULL,
	0xd91dd2e13ce144afULL, 0x92c6e9ed90d2eb35ULL, 0x0680447a8e5ff9a6ULL,
};

} // namespace

extern "C" {

// Scott's test [-z^2]P == sigma^2(P) on 16 affine points per step (n % 16 == 0).
// Reports how many lanes matched sigma(P) and sigma^2(P), to pin which root mcl's rw() is.
void proto_in_g1_16(const void* pts, size_t n, int* match_sigma1, int* match_sigma2)
{
	const G1A* x = (const G1A*)pts;
	int m1 = 0, m2 = 0;
	for (size_t i = 0; i < n; i += 16) {
		EcMA P, R1, R2, S1, S2;
		P.setG1A<true>(x + i, false);
		mulZ<true>(R1, P);
		mulZ<false>(R2, R1);
		EcMA::neg(R2, R2);
		EcMA::mulLambda(S1, P);
		EcMA::mulLambda(S2, S1);
		m1 += popcnt16(R2.isEqualJacobiAll(S1));
		m2 += popcnt16(R2.isEqualJacobiAll(S2));
	}
	*match_sigma1 = m1;
	*match_sigma2 = m2;
}

// y = x^((p+1)/4) on 16 lanes per step with a shared 4-bit exponent window; returns
// the number of lanes where y^2 == x.
int proto_sqrt_16(const void* xs, size_t n, void* ys)
{
	const FpA* x = (const FpA*)xs;
	FpA* y = (FpA*)ys;
	int ok = 0;
	for (size_t i = 0; i < n; i += 16) {
		FpMA b, r, t, tbl[16];
		b.setFpA(x + i);
		tbl[0] = FpMA::one();
		tbl[1] = b;
		for (int k = 2; k < 16; k++) FpMA::mul(tbl[k], tbl[k - 1], b);
		r = tbl[(g_sqrtExp[(94 * 4) / 64] >> ((94 * 4) % 64)) & 15];
		for (int w = 93; w >= 0; w--) {
			int d = (int)((g_sqrtExp[(w * 4) / 64] >> ((w * 4) % 64)) & 15);
			for (int s = 0; s < 4; s++) FpMA::sqr(r, r);
			if (d) FpMA::mul(r, r, tbl[d]);
		}
		FpMA::sqr(t, r);
		ok += popcnt16(t.isEqualAll(b));
		r.getFpA(y + i);
	}
	return ok;
}

} // extern "C"
