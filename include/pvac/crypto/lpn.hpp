#pragma once

#include <cstdint>
#include <vector>
#include <string>

#include "../core/types.hpp"
#include "../core/hash.hpp"
#include "toeplitz.hpp"

namespace pvac {

// 128 bit
inline Fp hash_to_fp_nonzero(uint64_t lo, uint64_t hi) {
    Fp r = fp_from_words(lo, hi & MASK63);
    if (r.lo == 0 && r.hi == 0) {
        r = fp_from_u64(1);
    }
    return r;
}

// prf_k + canon_tag + H_digest + seed
inline std::vector<uint64_t> build_prf_key(
    const PubKey& pk,
    const SecKey& sk,
    const RSeed& seed
) {
    std::vector<uint64_t> key;
    key.reserve(sk.prf_k.size() + 1 + 4 + 3);

    for (auto x : sk.prf_k) {
        key.push_back(x);
    }

    key.push_back(pk.canon_tag);

    const uint8_t* d = pk.H_digest.data();
    key.push_back(load_le64(d + 0));
    key.push_back(load_le64(d + 8));
    key.push_back(load_le64(d + 16));
    key.push_back(load_le64(d + 24));

    key.push_back(seed.ztag);
    key.push_back(seed.nonce.lo);
    key.push_back(seed.nonce.hi);

    return key;
}

// y[r] = <random_row, s> xor e, noise rate = tau
inline void lpn_make_ybits(
    const PubKey& pk,
    const SecKey& sk,
    const RSeed& seed,
    const char* dom,
    std::vector<uint64_t>& ybits
) {
    int t = pk.prm.lpn_t;
    int n = pk.prm.lpn_n;
    size_t s_words = (n + 63) / 64;

    auto key = build_prf_key(pk, sk, seed);

    XofShake xof;
    xof.init(std::string(dom), key);

    ybits.assign(((size_t)t + 63) / 64, 0ull);

    int num = pk.prm.lpn_tau_num;
    int den = pk.prm.lpn_tau_den;

    for (int r = 0; r < t; r++) {
        int dot = 0;
        for (size_t wi = 0; wi < s_words; ++wi) {
            uint64_t row = xof.take_u64();
            dot ^= parity64(row & sk.lpn_s_bits[wi]);
        }

        int e = (xof.bounded((uint64_t)den) < (uint64_t)num) ? 1 : 0;
        int y = dot ^ e;

        ybits[r >> 6] ^= ((uint64_t)y) << (r & 63);
    }
}

// toeplitz comp
inline Fp prf_R_core(
    const PubKey& pk,
    const SecKey& sk,
    const RSeed& seed,
    const char* dom
) {
    std::vector<uint64_t> ybits;
    lpn_make_ybits(pk, sk, seed, dom, ybits);

    auto seed_words = build_prf_key(pk, sk, seed);

    XofShake xof;
    xof.init(std::string(Dom::TOEP), seed_words);

    size_t top_words = ((size_t)pk.prm.lpn_t + 127 + 63) / 64;

    for (;;) {
        std::vector<uint64_t> top(top_words);
        for (size_t i = 0; i < top_words; i++) {
            top[i] = xof.take_u64();
        }

        uint64_t lo = 0, hi = 0;
        toep_127(top, ybits, lo, hi);

        Fp r = hash_to_fp_nonzero(lo, hi);
        if (!(r.lo == 0 && r.hi == 0)) {
            return r;
        }
    }
}

// r1 * r2 * r3 
inline Fp prf_R(const PubKey& pk, const SecKey& sk, const RSeed& seed) {
    Fp r1 = prf_R_core(pk, sk, seed, Dom::PRF_R1);
    Fp r2 = prf_R_core(pk, sk, seed, Dom::PRF_R2);
    Fp r3 = prf_R_core(pk, sk, seed, Dom::PRF_R3);

    // need to check _MUL_024F for all x (!!!!)
    return fp_mul(fp_mul(r1, r2), r3);
}

}