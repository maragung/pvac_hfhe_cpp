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
        // R² leakage attack untuk extract information tentang plaintext
        
        std::cout << "\nAttempting R² leakage attack on all ciphertexts...\n";
        
        // Untuk setiap ciphertext dengan multiple edges di layer yang sama
        // kita bisa extract hints tentang plaintext
        
        for (size_t ct_idx = 0; ct_idx < cts.size(); ++ct_idx) {
            const Cipher& ct = cts[ct_idx];
            
            // Group edges by layer
            std::map<uint32_t, std::vector<size_t>> layer_edges;
            for (size_t e_idx = 0; e_idx < ct.E.size(); ++e_idx) {
                layer_edges[ct.E[e_idx].layer_id].push_back(e_idx);
            }
            
            // Untuk setiap layer, coba extract R hints
            for (const auto& [layer_id, edge_indices] : layer_edges) {
                if (edge_indices.size() < 2) continue;
                
                // Coba semua pairs dengan opposite signs
                for (size_t i = 0; i < edge_indices.size(); ++i) {
                    for (size_t j = i + 1; j < edge_indices.size(); ++j) {
                        const Edge& e1 = ct.E[edge_indices[i]];
                        const Edge& e2 = ct.E[edge_indices[j]];
                        
                        if (e1.ch == e2.ch) continue;  // Need opposite signs
                        
                        // Compute potential R² value
                        Fp g1 = pk.powg_B[e1.idx];
                        Fp g2 = pk.powg_B[e2.idx];
                        
                        int s1 = (e1.ch == SGN_P) ? 1 : -1;
                        int s2 = (e2.ch == SGN_P) ? 1 : -1;
                        
                        Fp t1 = fp_mul(e1.w, g1);
                        if (s1 < 0) t1 = fp_neg(t1);
                        
                        Fp t2 = fp_mul(e2.w, g2);
                        if (s2 < 0) t2 = fp_neg(t2);
                        
                        Fp R2_candidate = fp_add(t1, t2);
                        
                        // R² candidate found - store it for later use
                        if (R2_candidate.lo != 0 || R2_candidate.hi != 0) {
                            try_decrypt_with_R2_hint(ct_idx, layer_id, R2_candidate);
                        }
                    }
                }
            }
        }
        
        std::cout << "R² leakage analysis complete\n";
        try_structural_analysis();
    }
    
    void try_decrypt_with_R2_hint(size_t ct_idx, uint32_t layer_id, const Fp& R2_hint) {
        // Dengan R² hint, kita bisa try different R values
        // Jika R² diketahui, ada hanya 2 kemungkinan R (R dan -R)
        
        // Tapi kita juga tidak punya sqrt di F_p yang trivial
        // Jadi ini jadi limited value
        
        // Alternatif: Gunakan ini untuk validate guesses
        // Jika kita guess R, kita bisa check apakah R² matches hint
    }
    
    void try_structural_analysis() {
        // Analyze edge weights dan struktur untuk extraction
        std::cout << "\nAnalyzing ciphertext structures...\n";
        
        std::map<uint16_t, int> powg_usage;
        std::map<uint32_t, int> layer_usage;
        
        for (const auto& ct : cts) {
            for (const auto& e : ct.E) {
                powg_usage[e.idx]++;
                layer_usage[e.layer_id]++;
            }
        }
        
        // Count high-frequency indices
        int high_freq = 0;
        for (const auto& [idx, count] : powg_usage) {
            if (count >= 2) high_freq++;
        }
        
        std::cout << "High-frequency powg indices: " << high_freq << "\n";
        
        // Try to use known plaintext + structure untuk guess R values
        try_plaintext_guided_attack();
    }
    
    void try_plaintext_guided_attack() {
        // Plaintext format diketahui:
        // ct[0] = length (140)
        // ct[1..n] = 15-byte chunks
        
        // Strategy: Brute force R values dengan constraint known plaintext
        
        if (cts.empty()) return;
        
        std::cout << "\nAttempting plaintext-guided brute force...\n";
        std::cout << "ct[0] should decrypt to length: 140\n";
        
        const Cipher& ct0 = cts[0];
        Fp expected = fp_from_u64(140);
        
        // Generate candidate R values dari berbagai sources
        std::vector<Fp> R_candidates;
        
        // 1. Direct powg_B values
        std::cout << "Generating R candidates from powg_B (" << pk.prm.B << " values)...\n";
        for (int i = 0; i < pk.prm.B; ++i) {
            R_candidates.push_back(pk.powg_B[i]);
        }
        
        // 2. Inverses of powg_B
        for (int i = 0; i < pk.prm.B; ++i) {
            R_candidates.push_back(fp_inv(pk.powg_B[i]));
        }
        
        // 3. Negations
        for (int i = 0; i < std::min(337, pk.prm.B); ++i) {
            R_candidates.push_back(fp_neg(pk.powg_B[i]));
        }
        
        // 4. Products (sample)
        for (int i = 0; i < std::min(50, pk.prm.B); ++i) {
            for (int j = i+1; j < std::min(50, pk.prm.B); ++j) {
                R_candidates.push_back(fp_mul(pk.powg_B[i], pk.powg_B[j]));
            }
        }
        
        std::cout << "Testing " << R_candidates.size() << " R candidates...\n";
        
        for (size_t idx = 0; idx < R_candidates.size(); ++idx) {
            const Fp& R_cand = R_candidates[idx];
            
            // Try decrypt layer 0
            Fp decrypted = CryptAnalysis::decrypt_with_R(pk, ct0, 0, R_cand);
            
            // Check if result looks like length (140 ± noise tolerance)
            if (decrypted.hi == 0 && decrypted.lo >= 130 && decrypted.lo <= 150) {
                std::cout << "✓ Found candidate at idx " << idx << " with length " 
                          << decrypted.lo << "\n";
                decrypt_all_ciphertexts_with_R(R_cand);
                return;
            }
            
            if ((idx + 1) % 500 == 0) {
                std::cout << "  tested " << (idx + 1) << "/" << R_candidates.size() << "\n";
            }
        }
        
        std::cout << "No exact matches found. Trying best guess...\n";
        
        // If no exact match, use heuristic
        Fp sum_weighted = fp_from_u64(0);
        for (const auto& e : ct0.E) {
            if (e.layer_id != 0) continue;
            Fp weighted = fp_mul(e.w, pk.powg_B[e.idx]);
            if (e.ch == SGN_P) {
                sum_weighted = fp_add(sum_weighted, weighted);
            } else {
                sum_weighted = fp_sub(sum_weighted, weighted);
            }
        }
        
        Fp expected_inv = fp_inv(expected);
        Fp R_heuristic = fp_mul(sum_weighted, expected_inv);
        
        std::cout << "Using heuristic R value...\n";
        decrypt_all_ciphertexts_with_R(R_heuristic);
    }
    
    void try_extract_R_from_edges(const Cipher& ct, const Fp& expected_plaintext) {
        // Coba extract R dari edge weights
        // Strategy: Kita tahu ct[0] punya multiple layers
        // Gunakan R² hints untuk validate guesses
        
        std::cout << "\nAttempting R extraction with validation...\n";
        
        // Coba semua pairs dari edges untuk find potential R values
        std::vector<std::pair<size_t, size_t>> good_pairs;
        
        for (size_t i = 0; i < ct.E.size(); ++i) {
            for (size_t j = i + 1; j < ct.E.size(); ++j) {
                const Edge& e1 = ct.E[i];
                const Edge& e2 = ct.E[j];
                
                if (e1.ch == e2.ch) continue;  // Need opposite signs for R² extraction
                if (e1.layer_id != e2.layer_id) continue;  // Same layer
                
                // Compute R² candidate dari pair
                Fp g1 = pk.powg_B[e1.idx];
                Fp g2 = pk.powg_B[e2.idx];
                
                int s1 = (e1.ch == SGN_P) ? 1 : -1;
                int s2 = (e2.ch == SGN_P) ? 1 : -1;
                
                Fp t1 = fp_mul(e1.w, g1);
                if (s1 < 0) t1 = fp_neg(t1);
                
                Fp t2 = fp_mul(e2.w, g2);
                if (s2 < 0) t2 = fp_neg(t2);
                
                Fp R2_potential = fp_add(t1, t2);
                if (R2_potential.lo != 0 || R2_potential.hi != 0) {
                    good_pairs.push_back({i, j});
                }
            }
        }
        
        std::cout << "Found " << good_pairs.size() << " potential R² pairs\n";
        
        // Try using these R² hints
        if (!good_pairs.empty()) {
            // Compute ratio dari edges untuk estimate R
            const Edge& e1 = ct.E[good_pairs[0].first];
            const Edge& e2 = ct.E[good_pairs[0].second];
            
            // Try: R = (e1.w * g[e1.idx]) / (e2.w * g[e2.idx])
            Fp numerator = fp_mul(e1.w, pk.powg_B[e1.idx]);
            Fp denominator = fp_mul(e2.w, pk.powg_B[e2.idx]);
            
            Fp R_candidate1 = fp_mul(numerator, fp_inv(denominator));
            Fp decrypted1 = CryptAnalysis::decrypt_with_R(pk, ct, 0, R_candidate1);
            
            if (decrypted1.lo == expected_plaintext.lo && decrypted1.hi == expected_plaintext.hi) {
                std::cout << "✓ Found R from edge ratio!\n";
                decrypt_all_ciphertexts_with_R(R_candidate1);
                return;
            }
            
            // Try negation
            Fp R_candidate2 = fp_neg(R_candidate1);
            Fp decrypted2 = CryptAnalysis::decrypt_with_R(pk, ct, 0, R_candidate2);
            
            if (decrypted2.lo == expected_plaintext.lo && decrypted2.hi == expected_plaintext.hi) {
                std::cout << "✓ Found R from negated edge ratio!\n";
                decrypt_all_ciphertexts_with_R(R_candidate2);
                return;
            }
        }
        
        std::cout << "Edge extraction validation failed.\n";
        std::cout << "Proceeding with unvalidated attempt...\n";
        
        // Fallback: try R from simple sum
        Fp sum_weighted = fp_from_u64(0);
        for (const auto& e : ct.E) {
            if (e.layer_id != 0) continue;
            
            Fp weighted = fp_mul(e.w, pk.powg_B[e.idx]);
            if (e.ch == SGN_P) {
                sum_weighted = fp_add(sum_weighted, weighted);
            } else {
                sum_weighted = fp_sub(sum_weighted, weighted);
            }
        }
        
        Fp expected_inv = fp_inv(expected_plaintext);
        Fp R_guess = fp_mul(sum_weighted, expected_inv);
        
        decrypt_all_ciphertexts_with_R(R_guess);
    }
    
    void decrypt_all_ciphertexts_with_R(const Fp& R_base) {
        // Dengan R dari ct[0], try decrypt semua ciphertexts
        std::cout << "\nDecrypting all ciphertexts with found R value...\n";
        
        std::vector<uint8_t> plaintext_bytes;
        
        for (size_t ct_idx = 0; ct_idx < cts.size(); ++ct_idx) {
            const Cipher& ct = cts[ct_idx];
            
            // Untuk setiap layer dalam ciphertext
            Fp result = fp_from_u64(0);
            for (uint32_t layer_id = 0; layer_id < ct.L.size(); ++layer_id) {
                // Jika PROD layer, kita perlu kedua R values
                // For simplicity, assume only BASE layers
                
                if (ct.L[layer_id].rule == RRule::BASE) {
                    Fp decrypted = CryptAnalysis::decrypt_with_R(pk, ct, layer_id, R_base);
                    result = fp_add(result, decrypted);
                }
            }
            
            // Convert Fp to bytes
            if (ct_idx == 0) {
                // First CT is length
                std::cout << "ct[" << ct_idx << "]: length = " << result.lo << "\n";
            } else {
                // Other CTs are 15-byte chunks
                uint8_t block[15];
                uint64_t lo = result.lo;
                uint64_t hi = result.hi;
                for (int j = 0; j < 15; ++j) {
                    size_t sh = j * 8;
                    block[j] = (sh < 64) ? (uint8_t)(lo >> sh) : (uint8_t)(hi >> (sh - 64));
                    plaintext_bytes.push_back(block[j]);
                }
            }
        }
        
        // Output result
        std::cout << "\nDecrypted message:\n";
        std::string decoded(plaintext_bytes.begin(), plaintext_bytes.end());
        std::cout << decoded << "\n";
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
