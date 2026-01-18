#include <pvac/pvac.hpp>
#include <pvac/utils/text.hpp>

#include <cstdint>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <cstring>
#include <map>
#include <set>
#include <algorithm>

using namespace pvac;
namespace fs = std::filesystem;

namespace Magic {
    constexpr uint32_t CT = 0x66699666;
    constexpr uint32_t SK = 0x66666999;
    constexpr uint32_t PK = 0x06660666;
    constexpr uint32_t VER = 1;
}

namespace io {
    auto get32 = [](std::istream& i) -> uint32_t {
        uint32_t x = 0;
        i.read(reinterpret_cast<char*>(&x), 4);
        return x;
    };

    auto get64 = [](std::istream& i) -> uint64_t {
        uint64_t x = 0;
        i.read(reinterpret_cast<char*>(&x), 8);
        return x;
    };

    auto getBv = [](std::istream& i) -> BitVec {
        auto b = BitVec::make((int)get32(i));
        for (size_t j = 0; j < (b.nbits + 63) / 64; ++j) b.w[j] = get64(i);
        return b;
    };

    auto getFp = [](std::istream& i) -> Fp {
        return { get64(i), get64(i) };
    };
}

namespace ser {
    using namespace io;

    auto getLayer = [](std::istream& i) -> Layer {
        Layer L{};
        L.rule = (RRule)i.get();
        if (L.rule == RRule::BASE) {
            L.seed.ztag = get64(i);
            L.seed.nonce.lo = get64(i);
            L.seed.nonce.hi = get64(i);
        } else if (L.rule == RRule::PROD) {
            L.pa = get32(i);
            L.pb = get32(i);
        }
        return L;
    };

    auto getEdge = [](std::istream& i) -> Edge {
        Edge e{};
        e.layer_id = get32(i);
        i.read(reinterpret_cast<char*>(&e.idx), 2);
        e.ch = i.get();
        i.get();
        e.w = getFp(i);
        e.s = getBv(i);
        return e;
    };

    auto getCipher = [](std::istream& i) -> Cipher {
        Cipher C;
        auto nL = get32(i), nE = get32(i);
        C.L.resize(nL);
        C.E.resize(nE);
        for (auto& L : C.L) L = getLayer(i);
        for (auto& e : C.E) e = getEdge(i);
        return C;
    };
}

auto loadCts = [](const std::string& path) -> std::vector<Cipher> {
    std::ifstream i(path, std::ios::binary);
    if (!i) throw std::runtime_error("cannot open " + path);
    auto magic = io::get32(i);
    auto ver = io::get32(i);
    if (magic != Magic::CT || ver != Magic::VER)
        throw std::runtime_error("bad ct header");
    std::vector<Cipher> cts(io::get64(i));
    for (auto& c : cts) c = ser::getCipher(i);
    return cts;
};

auto loadPk = [](const std::string& path) -> PubKey {
    std::ifstream i(path, std::ios::binary);
    if (!i) throw std::runtime_error("cannot open " + path);
    auto magic = io::get32(i);
    auto ver = io::get32(i);
    if (magic != Magic::PK || ver != Magic::VER)
        throw std::runtime_error("bad pk header");

    PubKey pk;
    pk.prm.m_bits = io::get32(i);
    pk.prm.B = io::get32(i);
    pk.prm.lpn_t = io::get32(i);
    pk.prm.lpn_n = io::get32(i);
    pk.prm.lpn_tau_num = io::get32(i);
    pk.prm.lpn_tau_den = io::get32(i);
    pk.prm.noise_entropy_bits = io::get32(i);
    pk.prm.depth_slope_bits = io::get32(i);
    pk.prm.tuple2_fraction = io::get64(i);
    pk.prm.edge_budget = io::get32(i);
    pk.canon_tag = io::get64(i);

    i.read(reinterpret_cast<char*>(pk.H_digest.data()), 32);
    pk.H.resize(io::get64(i));
    for (auto& h : pk.H) h = io::getBv(i);
    pk.ubk.perm.resize(io::get64(i));
    for (auto& v : pk.ubk.perm) v = io::get32(i);
    pk.ubk.inv.resize(io::get64(i));
    for (auto& v : pk.ubk.inv) v = io::get32(i);
    pk.omega_B = io::getFp(i);
    pk.powg_B.resize(io::get64(i));
    for (auto& f : pk.powg_B) f = io::getFp(i);
    return pk;
};

// Structure to analyze layers and edges
struct LayerInfo {
    std::vector<size_t> edge_indices;
    std::set<uint16_t> powg_indices;
    uint32_t layer_id;
    RRule rule;
};

// Cryptanalytic tools for attacking the ciphertext
struct CryptAnalysis {
    // R² leakage attack: find R values from edge pairs with opposite signs
    static std::map<uint32_t, Fp> find_R_squared_candidates(const PubKey& pk, const Cipher& ct) {
        std::map<uint32_t, std::vector<const Edge*>> layer_edges;
        std::map<uint32_t, Fp> R_squared_candidates;
        
        // Group edges by layer
        for (const auto& e : ct.E) {
            layer_edges[e.layer_id].push_back(&e);
        }
        
        // For each layer, look for R² leakage
        for (const auto& [layer_id, edges] : layer_edges) {
            if (edges.size() < 2) continue;
            
            // Look for opposite-sign pairs
            for (size_t i = 0; i < edges.size(); ++i) {
                for (size_t j = i + 1; j < edges.size(); ++j) {
                    const Edge& e1 = *edges[i];
                    const Edge& e2 = *edges[j];
                    
                    if (e1.ch == e2.ch) continue;  // Need opposite signs
                    
                    // For opposite signs:
                    // e1.w * g^e1.idx / R_inv = -e2.w * g^e2.idx / R_inv
                    // => e1.w * g^e1.idx + e2.w * g^e2.idx = R² * (something)
                    
                    int s1 = (e1.ch == 0) ? 1 : -1;
                    int s2 = (e2.ch == 0) ? 1 : -1;
                    
                    Fp t1 = fp_mul(e1.w, pk.powg_B[e1.idx]);
                    Fp t2 = fp_mul(e2.w, pk.powg_B[e2.idx]);
                    
                    if (s1 < 0) t1 = fp_neg(t1);
                    if (s2 < 0) t2 = fp_neg(t2);
                    
                    // Try to find R² from the combination
                    Fp cand = fp_add(t1, t2);
                    if (cand.lo != 0 || cand.hi != 0) {
                        R_squared_candidates[layer_id] = cand;
                    }
                }
            }
        }
        
        return R_squared_candidates;
    }
    
    // Try to decrypt layer using candidate R value
    static Fp decrypt_with_R(const PubKey& pk, const Cipher& ct, uint32_t layer_id, const Fp& R) {
        if (R.lo == 0 && R.hi == 0) return fp_from_u64(0);
        
        Fp R_inv = fp_inv(R);
        Fp sum = fp_from_u64(0);
        
        for (const auto& e : ct.E) {
            if (e.layer_id != layer_id) continue;
            
            Fp term = fp_mul(e.w, R_inv);
            term = fp_mul(term, pk.powg_B[e.idx]);
            
            if (e.ch == 0) {  // SGN_P
                sum = fp_add(sum, term);
            } else {  // SGN_M
                sum = fp_sub(sum, term);
            }
        }
        
        return sum;
    }
};

// Known-plaintext attack: try to match observed structures with known text patterns
struct KnownPlaintextAttack {
    const PubKey& pk;
    const std::vector<Cipher>& cts;
    std::map<std::string, int> mnemonic_dict;

    KnownPlaintextAttack(const PubKey& pk, const std::vector<Cipher>& cts)
        : pk(pk), cts(cts) {
        // Common BIP39 words for mnemonic phrases
        const char* common_words[] = {
            "abandon", "ability", "able", "about", "above", "absent", "absolute", "absorb",
            "abstract", "absurd", "access", "accident", "account", "accuse", "achieve", "acid",
            "acoustic", "acquire", "across", "act", "action", "activate", "active", "actor",
            "acts", "actual", "acumen", "acute", "ad", "adapt", "add", "addict", "added",
            "adder", "addicted", "adding", "addition", "additive", "address", "adds", "adept",
            "adequate", "adhere", "adherent", "adhesive", "adipose", "adjacent", "adjective",
            "adjoin", "adjoining", "adjoint", "adjourn", "adjudge", "adjudicate", "adjunct",
            "adjuration", "adjure", "adjust", "adjustable", "adjuster", "adjustment", "adjuvant",
            "admensuration", "administer", "administrable", "administrant", "administrate",
            "administration", "administrative", "administrator", "admirable", "admirably", "admiral",
            "admiralty", "admiration", "admire", "admirer", "admiring", "admissibility",
            "admissible", "admission", "admit", "admittance", "admitted", "admittedly", "admitter",
            "admixture", "admonish", "admonishment", "admonition", "admonitory", "ad", "nauseam"
        };
        for (size_t i = 0; i < sizeof(common_words)/sizeof(common_words[0]); ++i) {
            mnemonic_dict[common_words[i]] = 1;
        }
    }

    // Analyze layer structure and try to recover hints about R values
    void analyze_structure() {
        std::cout << "--- Starting Known-Plaintext/Intersection Attack ---\n";

        std::set<uint32_t> all_layers;
        std::map<uint32_t, LayerInfo> layer_info;

        for (size_t ct_idx = 0; ct_idx < cts.size(); ++ct_idx) {
            const Cipher& ct = cts[ct_idx];
            for (size_t e_idx = 0; e_idx < ct.E.size(); ++e_idx) {
                const Edge& e = ct.E[e_idx];
                all_layers.insert(e.layer_id);
                if (layer_info.find(e.layer_id) == layer_info.end()) {
                    layer_info[e.layer_id].layer_id = e.layer_id;
                    if (e.layer_id < ct.L.size()) {
                        layer_info[e.layer_id].rule = ct.L[e.layer_id].rule;
                    }
                }
                layer_info[e.layer_id].edge_indices.push_back(e_idx);
                layer_info[e.layer_id].powg_indices.insert(e.idx);
            }
        }

        std::cout << "Unique layers found: " << all_layers.size() << "\n";

        // Analyze ciphertext structure for potential weaknesses
        for (size_t ct_idx = 0; ct_idx < cts.size(); ++ct_idx) {
            const Cipher& ct = cts[ct_idx];
            int base_layers = 0;
            for (const auto& l : ct.L) {
                if (l.rule == RRule::BASE) base_layers++;
            }
        }

        // Perform intersection attack
        crack_by_intersection();
    }

    void crack_by_intersection() {
        // Strategy: Gunakan R² leakage attack untuk extract R values
        // Kemudian decrypt ciphertexts dengan R values yang ditemukan
        
        std::cout << "\nAttempting R² leakage attack on all ciphertexts...\n";
        
        std::map<uint32_t, Fp> all_R_squared;
        std::vector<std::map<uint32_t, Fp>> ct_R_squared(cts.size());
        
        // Extract R² values dari setiap ciphertext
        for (size_t ct_idx = 0; ct_idx < cts.size(); ++ct_idx) {
            auto R2_cand = CryptAnalysis::find_R_squared_candidates(pk, cts[ct_idx]);
            ct_R_squared[ct_idx] = R2_cand;
            
            for (const auto& [layer_id, R2] : R2_cand) {
                all_R_squared[layer_id] = R2;
            }
        }
        
        std::cout << "Found " << all_R_squared.size() << " R² candidates\n";
        
        // Try to use R² values to derive R values
        // This requires solving sqrt in F_p, which is complex
        // Alternative: brute force search space menggunakan known plaintext format
        
        try_brute_force_with_constraints();
    }

    void try_brute_force_with_constraints() {
        // Plaintext format diketahui: "mnemonic: (...), number: (...)"
        // Panjang totalnya 140 bytes
        
        // Strategy: 
        // 1. Ciphertext pertama adalah length (140)
        // 2. Ciphertext berikutnya adalah 15-byte chunks
        // 3. Format string sudah diketahui sebagian
        
        std::cout << "\nAnalyzing plaintext structure...\n";
        
        // Strategi attack: Jika BASE layers tidak terlalu banyak,
        // kita bisa mencoba brute force nilai-nilai yang masuk akal
        
        // Hitung struktur ciphertext
        std::vector<int> ct_layers;
        std::vector<int> ct_edges;
        
        for (size_t i = 0; i < cts.size(); ++i) {
            ct_layers.push_back(cts[i].L.size());
            ct_edges.push_back(cts[i].E.size());
            std::cout << "  ct[" << i << "]: " << cts[i].L.size() << " layers, " 
                      << cts[i].E.size() << " edges\n";
        }
        
        // Try attack: Jika semua ciphertext share layer structure
        // mungkin ada kesamaan yang bisa diexploit
        
        // Get first BASE layer dari first ciphertext
        if (!cts.empty() && !cts[0].L.empty()) {
            const Cipher& ct0 = cts[0];
            
            // Coba extract dari layer 0
            if (ct0.L[0].rule == RRule::BASE) {
                std::cout << "\nFirst ciphertext uses BASE layer at 0\n";
                
                // Try different R value guesses
                // Known pattern: decrypted value should be length (140)
                
                // Untuk BASE layer, R = prf_R(pk, sk, seed)
                // Tapi kita tidak punya sk
                
                // Alternative: Try structured guesses
                // Jika ada pattern dalam edge weights, kita bisa exploit
                
                std::cout << "Analyzing edge patterns in first ciphertext...\n";
                
                std::map<uint16_t, int> idx_freq;
                for (const auto& e : ct0.E) {
                    idx_freq[e.idx]++;
                }
                
                int max_freq = 0;
                uint16_t max_idx = 0;
                for (const auto& [idx, freq] : idx_freq) {
                    if (freq > max_freq) {
                        max_freq = freq;
                        max_idx = idx;
                    }
                }
                
                std::cout << "Most frequent powg index: " << max_idx 
                          << " (appears " << max_freq << " times)\n";
                
                // Try to use this information for guessing
                // Plaintext untuk ct[0] adalah panjang (140 = 0x8C)
                
                Fp expected_value = fp_from_u64(140);
                std::cout << "Expected plaintext for ct[0]: " << expected_value.lo << "\n";
            }
        }
        
        // Compute brute force search space estimates
        int total_base_layers = 0;
        for (const auto& ct : cts) {
            for (const auto& l : ct.L) {
                if (l.rule == RRule::BASE) total_base_layers++;
            }
        }
        
        std::cout << "\nTotal BASE layers across all ciphertexts: " << total_base_layers << "\n";
        std::cout << "Search space for R values per layer: 2^127\n";
        std::cout << "Combined search space: 2^" << (127 * total_base_layers) << "\n";
        
        // Attempt meet-in-the-middle if feasible
        if (total_base_layers <= 4) {
            std::cout << "\nSearch space is potentially explorable with meet-in-the-middle...\n";
            perform_meet_in_middle();
        } else {
            std::cout << "\nSearch space too large for brute force.\n";
            std::cout << "Would need quantum algorithms or algebraic attacks.\n";
        }
        
        std::cout << "\nResult: Unable to fully break ciphertext with current methods\n";
        std::cout << "But found " << total_base_layers << " BASE layers (attack surface)\n";
    }
    
    void perform_meet_in_middle() {
        // Meet-in-the-middle attack:
        // 1. Generate first half of R values
        // 2. Check consistency with second half
        // 3. Use known plaintext constraints to filter
        
        std::cout << "  (Meet-in-the-middle would require actual R enumeration)\n";
        std::cout << "  (Skipping due to exponential search space)\n";
    }
};

int main(int argc, char** argv) {
    std::string dir = (argc > 1) ? argv[1] : "bounty3_data";

    std::cout << "- solve bounty3 -\n";
    std::cout << "dir: " << dir << "\n\n";

    if (!fs::exists(dir)) {
        std::cout << "dir not found\n";
        return 1;
    }

    auto ct_path = dir + "/seed.ct";
    auto pk_path = dir + "/pk.bin";

    bool has_ct = fs::exists(ct_path);
    bool has_pk = fs::exists(pk_path);

    if (!has_ct || !has_pk) {
        std::cout << "missing ciphertext or public key\n";
        return 1;
    }

    std::vector<Cipher> cts;
    PubKey pk;

    try {
        cts = loadCts(ct_path);
        pk = loadPk(pk_path);
        std::cout << "loaded pk:   B = " << pk.prm.B << " m_bits = " << pk.prm.m_bits 
                  << " n_bits = " << pk.prm.lpn_n << "\n";
        std::cout << "loaded " << cts.size() << " CTs\n";
        std::cout << "pk.B = " << pk.prm.B << " pk.H=" << pk.H.size() << "\n\n";
    } catch (const std::exception& e) {
        std::cout << "load failed: " << e.what() << "\n";
        return 1;
    }

    // Run the attack
    KnownPlaintextAttack attacker(pk, cts);
    attacker.analyze_structure();

    std::cout << "\nNOTE: This is a structural analysis framework for attacking bounty3.\n";
    std::cout << "To fully solve this challenge, you would need to:\n";
    std::cout << "1. Implement quantum/classical algorithms for breaking LPN assumption\n";
    std::cout << "2. Exploit implementation-specific vulnerabilities\n";
    std::cout << "3. Use side-channel information if available\n";
    std::cout << "4. Implement more sophisticated cryptanalysis techniques\n";

    return 0;
}
