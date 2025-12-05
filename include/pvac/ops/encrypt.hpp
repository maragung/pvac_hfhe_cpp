#pragma once

#include <cstdint>
#include <cmath>
#include <vector>
#include <unordered_set>
#include <utility>

#include "../core/types.hpp"
#include "../crypto/lpn.hpp"
#include "../crypto/matrix.hpp"
#include "../core/ct_safe.hpp"

namespace pvac {

inline std::pair<int, int> plan_noise(const PubKey& pk, int depth_hint) {
    double budget = pk.prm.noise_entropy_bits +
                    pk.prm.depth_slope_bits * std::max(0, depth_hint);

    double per2 = 2.0 * std::log2((double)pk.prm.B);
    double per3 = 3.0 * std::log2((double)pk.prm.B);

    int z2 = (int)std::floor((budget * pk.prm.tuple2_fraction) / std::max(1e-6, per2));
    int z3 = (int)std::floor((budget * (1.0 - pk.prm.tuple2_fraction)) / std::max(1e-6, per3));

    return { std::max(0, z2), std::max(0, z3) };
}

inline double sigma_density(const PubKey& pk, const Cipher& C) {
    long double ones = 0;
    long double total = 0;

    for (const auto& e : C.E) {
        ones += e.s.popcnt();
        total += (long double)pk.prm.m_bits;
    }

    return (total == 0) ? 0.0 : (double)(ones / total);
}

inline void compact_edges(const PubKey& pk, Cipher& C) {
    int B = pk.prm.B;
    size_t L = C.L.size();

    struct Agg {
        bool have_p = false;
        bool have_m = false;
        Fp wp, wm;
        BitVec sp, sm;
    };

    std::vector<Agg> acc(L * (size_t)B);

    for (const auto& e : C.E) {
        Agg& a = acc[(size_t)e.layer_id * B + e.idx];

        if (e.ch == SGN_P) {
            if (!a.have_p) {
                a.wp = fp_from_u64(0);
                a.sp = BitVec::make(pk.prm.m_bits);
                a.have_p = true;
            }
            a.wp = fp_add(a.wp, e.w);
            a.sp.xor_with(e.s);
        } else {
            if (!a.have_m) {
                a.wm = fp_from_u64(0);
                a.sm = BitVec::make(pk.prm.m_bits);
                a.have_m = true;
            }
            a.wm = fp_add(a.wm, e.w);
            a.sm.xor_with(e.s);
        }
    }

    std::vector<Edge> out;
    out.reserve(C.E.size());

    auto nz = [&](const Fp& w, const BitVec& s) {
        return ct::fp_is_nonzero(w) || (s.popcnt() != 0);
    };

    for (size_t lid = 0; lid < L; lid++) {
        for (int k = 0; k < B; k++) {
            Agg& a = acc[lid * (size_t)B + (size_t)k];

            if (a.have_p && nz(a.wp, a.sp)) {
                out.push_back(Edge{(uint32_t)lid, (uint16_t)k, SGN_P, a.wp, a.sp});
            }
            if (a.have_m && nz(a.wm, a.sm)) {
                out.push_back(Edge{(uint32_t)lid, (uint16_t)k, SGN_M, a.wm, a.sm});
            }
        }
    }

    C.E.swap(out);
}

inline void compact_layers(Cipher& C) {
    const size_t L = C.L.size();
    if (L == 0) return;

    std::vector<uint8_t> used(L, 0);
    for (const auto& e : C.E)
        if (e.layer_id < L) used[e.layer_id] = 1;

    for (bool changed = true; changed; ) {
        changed = false;
        for (size_t lid = 0; lid < L; ++lid) {
            if (!used[lid] || C.L[lid].rule != RRule::PROD) continue;
            auto mark = [&](uint32_t p) {
                if (p < L && !used[p]) { used[p] = 1; changed = true; }
            };
            mark(C.L[lid].pa);
            mark(C.L[lid].pb);
        }
    }

    std::vector<uint32_t> remap(L, UINT32_MAX);
    std::vector<Layer> newL;
    newL.reserve(L);

    for (size_t lid = 0; lid < L; ++lid)
        if (used[lid]) { remap[lid] = (uint32_t)newL.size(); newL.push_back(C.L[lid]); }

    if (newL.size() == L) return;

    for (auto& Lr : newL)
        if (Lr.rule == RRule::PROD) { Lr.pa = remap[Lr.pa]; Lr.pb = remap[Lr.pb]; }

    for (auto& e : C.E) e.layer_id = remap[e.layer_id];

    C.L.swap(newL);
}

inline void guard_budget(const PubKey& pk, Cipher& C, const char* where) {
    if (C.E.size() > pk.prm.edge_budget) {
        if (g_dbg) std::cout << "[guard] " << where << ": " << C.E.size() << " -> compact\n";
        compact_edges(pk, C);
    }
}

inline Cipher enc_fp_depth(const PubKey& pk, const SecKey& sk, const Fp& v, int depth_hint) {
    Cipher C;

    Layer L;
    L.rule = RRule::BASE;
    L.seed.nonce = make_nonce128();
    L.seed.ztag = prg_layer_ztag(pk.canon_tag, L.seed.nonce);
    C.L.push_back(L);

    const int S = 8;

    std::vector<int> idx(S);
    std::unordered_set<int> used;
    used.reserve(S * 2);

    for (int j = 0; j < S; j++) {
        int x;
        do { x = (int)(csprng_u64() % (uint64_t)pk.prm.B); } while (used.count(x));
        used.insert(x);
        idx[j] = x;
    }

    std::vector<uint8_t> ch(S);
    for (int i = 0; i < S; i++) ch[i] = (uint8_t)(csprng_u64() & 1ull);

    std::vector<Fp> r(S);
    Fp sum1 = fp_from_u64(0);
    Fp sumg = fp_from_u64(0);

    for (int j = 0; j < S - 2; j++) {
        r[j] = rand_fp_nonzero();
        int s = sgn_val(ch[j]);
        sum1 = (s > 0) ? fp_add(sum1, r[j]) : fp_sub(sum1, r[j]);
        Fp term = fp_mul(r[j], pk.powg_B[idx[j]]);
        sumg = (s > 0) ? fp_add(sumg, term) : fp_sub(sumg, term);
    }

    int ia = idx[S - 2], ib = idx[S - 1];
    uint8_t sa_ch = ch[S - 2], sb_ch = ch[S - 1];
    int sa = sgn_val(sa_ch), sb = sgn_val(sb_ch);

    Fp ga = pk.powg_B[ia], gb = pk.powg_B[ib];
    Fp V = fp_sub(v, sumg);
    Fp rhs = fp_sub(fp_neg(fp_mul(sum1, ga)), V);
    Fp den = fp_sub(ga, gb);
    Fp rb = fp_mul(rhs, fp_inv(den));

    if (sb < 0) rb = fp_neg(rb);

    Fp tmp = (sb > 0) ? fp_sub(fp_neg(sum1), rb) : fp_add(fp_neg(sum1), rb);
    Fp ra = (sa > 0) ? tmp : fp_neg(tmp);

    r[S - 2] = ra;
    r[S - 1] = rb;

    Fp R = prf_R(pk, sk, L.seed);

    for (int j = 0; j < S; j++) {
        C.E.push_back(Edge{
            0, (uint16_t)idx[j], ch[j], fp_mul(r[j], R),
            sigma_from_H(pk, L.seed.ztag, L.seed.nonce, (uint16_t)idx[j], ch[j], csprng_u64())
        });
    }

    auto [Z2, Z3] = plan_noise(pk, depth_hint);

    // z2 noise (pairs)
    for (int t = 0; t < Z2; t++) {
        int i = (int)(csprng_u64() % (uint64_t)pk.prm.B);
        int j;
        do { j = (int)(csprng_u64() % (uint64_t)pk.prm.B); } while (j == i);

        Fp alpha = rand_fp_nonzero();
        Fp wi = fp_mul(alpha, R);
        Fp gamma = fp_mul(alpha, fp_mul(pk.powg_B[i], fp_inv(pk.powg_B[j])));
        Fp wj = fp_mul(gamma, R);

        // rnd sign ordering for z2
        uint8_t s1 = (uint8_t)(csprng_u64() & 1);
        uint8_t s2 = s1 ^ 1;

        C.E.push_back(Edge{0, (uint16_t)i, s1, wi,
            sigma_from_H(pk, L.seed.ztag, L.seed.nonce, (uint16_t)i, s1, csprng_u64())});
        C.E.push_back(Edge{0, (uint16_t)j, s2, wj,
            sigma_from_H(pk, L.seed.ztag, L.seed.nonce, (uint16_t)j, s2, csprng_u64())});
    }

    // z3 noise (triples) with random signs
    for (int t = 0; t < Z3; t++) {
        int i = (int)(csprng_u64() % (uint64_t)pk.prm.B);
        int j, k;
        do { j = (int)(csprng_u64() % (uint64_t)pk.prm.B); } while (j == i);
        do { k = (int)(csprng_u64() % (uint64_t)pk.prm.B); } while (k == i || k == j);

        uint8_t s1 = (uint8_t)(csprng_u64() & 1);
        uint8_t s2 = (uint8_t)(csprng_u64() & 1);
        uint8_t s3 = (uint8_t)(csprng_u64() & 1);

        int sign1 = sgn_val(s1), sign2 = sgn_val(s2), sign3 = sgn_val(s3);

        Fp a = rand_fp_nonzero();
        Fp b = rand_fp_nonzero();

        Fp term1 = fp_mul(a, pk.powg_B[i]);
        Fp term2 = fp_mul(b, pk.powg_B[j]);

        Fp sum = fp_add(
            (sign1 > 0) ? term1 : fp_neg(term1),
            (sign2 > 0) ? term2 : fp_neg(term2)
        );

        Fp gk = pk.powg_B[k];
        Fp divisor = (sign3 > 0) ? gk : fp_neg(gk);
        Fp c = fp_mul(fp_neg(sum), fp_inv(divisor));

        C.E.push_back(Edge{0, (uint16_t)i, s1, fp_mul(a, R),
            sigma_from_H(pk, L.seed.ztag, L.seed.nonce, (uint16_t)i, s1, csprng_u64())});
        C.E.push_back(Edge{0, (uint16_t)j, s2, fp_mul(b, R),
            sigma_from_H(pk, L.seed.ztag, L.seed.nonce, (uint16_t)j, s2, csprng_u64())});
        C.E.push_back(Edge{0, (uint16_t)k, s3, fp_mul(c, R),
            sigma_from_H(pk, L.seed.ztag, L.seed.nonce, (uint16_t)k, s3, csprng_u64())});
    }

    guard_budget(pk, C, "enc");
    return C;
}

// helper to combine two ct (inline ct_add to avoid circular dependency)
inline Cipher combine_ciphers(const PubKey& pk, const Cipher& a, const Cipher& b) {
    Cipher C;
    C.L.reserve(a.L.size() + b.L.size());
    C.E.reserve(a.E.size() + b.E.size());

    for (const auto& L : a.L) C.L.push_back(L);
    uint32_t off = (uint32_t)a.L.size();

    for (auto L : b.L) {
        if (L.rule == RRule::PROD) { L.pa += off; L.pb += off; }
        C.L.push_back(L);
    }

    for (const auto& e : a.E) C.E.push_back(e);
    for (auto e : b.E) { e.layer_id += off; C.E.push_back(std::move(e)); }

    guard_budget(pk, C, "combine");
    compact_layers(C);
    return C;
}


// all (!!!) values use same structure
inline Cipher enc_value_depth(const PubKey& pk, const SecKey& sk,
                              uint64_t v_u64, int depth_hint) {
    Fp val  = fp_from_u64(v_u64);
    Fp mask = rand_fp_nonzero();
    Cipher c_pos = enc_fp_depth(pk, sk, fp_add(val, mask), depth_hint);
    Cipher c_neg = enc_fp_depth(pk, sk, fp_neg(mask), depth_hint);
    return combine_ciphers(pk, c_pos, c_neg);
}

// enc(v) = enc(v + mask) + enc(-mask)
inline Cipher enc_value(const PubKey& pk, const SecKey& sk, uint64_t v) {
    return enc_value_depth(pk, sk, v, 0);
}

inline Cipher enc_zero_depth(const PubKey& pk, const SecKey& sk, int depth_hint) {
    // enc(0) = enc(mask) + enc(-mask)
    Fp mask = rand_fp_nonzero();
    Cipher c_pos = enc_fp_depth(pk, sk, mask, depth_hint);
    Cipher c_neg = enc_fp_depth(pk, sk, fp_neg(mask), depth_hint);
    return combine_ciphers(pk, c_pos, c_neg);
}

}