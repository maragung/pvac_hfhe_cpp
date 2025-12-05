#include <iostream>
#include <pvac/pvac.hpp>

using namespace pvac;

// 

Fp aggregator_sum(const PubKey& pk, const Cipher& c) {
    Fp sum = fp_from_u64(0);
    for (const auto& e : c.E) {
        if (e.layer_id != 0) continue; // only base layer (!)
        Fp term = fp_mul(e.w, pk.powg_B[e.idx]);
        sum = (e.ch == SGN_P) ? fp_add(sum, term) : fp_sub(sum, term);
    }
    return sum;
}

int main() {
    Params prm;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);
    
    std::cout << " - IND-CPA zero test -\n\n";
    
    for (int v : {0, 1, 2, 42, 100}) {
        Cipher c = enc_value(pk, sk, v);
        Fp S = aggregator_sum(pk, c);
        
        std::cout << "enc(" << v << "): S.lo = " << S.lo 
                  << ", S.hi = " << S.hi
                  << " -> " << ((S.lo == 0 && S.hi == 0) ? "zero" : "non-zero")
                  << "\n";
    }
    
    std::cout << "\ndec check:\n";
    for (int v : {0, 1, 42}) {
        Cipher c = enc_value(pk, sk, v);
        Fp dec = dec_value(pk, sk, c);
        std::cout << "dec(enc(" << v << ")) = " << dec.lo << "\n";
    }
    
    return 0;
}