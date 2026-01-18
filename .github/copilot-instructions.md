# PVAC-HFHE C++ Codebase Instructions

## Project Overview
**pvac-hfhe-cpp** is a proof-of-concept C++ implementation of public-key homomorphic encryption based on the binary parity Learning With Noise (LPN) assumption. The cryptosystem operates on a 127-bit prime field and uses syndrome graphs from k-uniform hypergraphs. This project demonstrates novel FHE constructions with emphasis on practical efficiency using PCLMUL instructions.

## Architecture

### Core Cryptographic Stack (include/pvac/)

**Key Components:**
- **core/**: Fundamental data structures and field operations
  - `types.hpp`: Core types (Cipher, Layer, Edge, PubKey, SecKey)
  - `field.hpp`: 127-bit prime field arithmetic using x86-64 PCLMUL
  - `bitvec.hpp`: BitVector operations for syndrome handling
  - `config.hpp`, `random.hpp`, `hash.hpp`

- **crypto/**: Cryptographic primitives
  - `lpn.hpp`: Learning With Noise implementation (key generation, syndrome computation)
  - `toeplitz.hpp`: Toeplitz matrix constructions for efficiency
  - `keygen.hpp`: Homomorphic key generation

- **ops/**: Homomorphic operations
  - `encrypt.hpp`: `enc_value()` and `enc_fp_depth()` - plaintext-to-ciphertext
  - `decrypt.hpp`: `dec_value()` - ciphertext-to-plaintext using secret key
  - `arithmetic.hpp`: Homomorphic addition/subtraction/multiplication
  - `recrypt.hpp`: Bootstrapping (recryption) for multi-level computation

- **utils/**: Practical utilities
  - `text.hpp`: String encryption/decryption in 15-byte blocks
  - `metrics.hpp`: Performance instrumentation

### Data Flow: Encryption
1. **Keygen**: Generate `Params` → `PubKey` + `SecKey` from PRF_k and random hypergraph
2. **Encryption**: Build DAG of computation layers (BASE/PROD rules) with deterministic PRF-seeded R values
3. **Edges**: Weighted graph edges encode plaintext via `powg_B` table (powers of generator)
4. **Noise**: Syndrome-based error added (not visible in plaintext recovery with sk)

### Data Flow: Decryption
- Decryption requires **secret key** (64-bit PRF seed for R computation)
- Without sk: ciphertext is intractable due to LPN security
- See decrypt.hpp: `layer_R_cached()` reconstructs R from Base/Prod rules, then scales edges

## Key Patterns & Conventions

### Cipher Structure
- **Layers** (`Layer`): Computation nodes with rules (BASE=seed-derived, PROD=child refs)
- **Edges** (`Edge`): Plaintext encoding as weighted graph edges (weight·pow(g,idx)·R_inv)
- **Layer Rules**:
  - `RRule::BASE`: R = prf_R(pk, sk, seed) [terminal]
  - `RRule::PROD`: R = R_pa · R_pb [composition]

### Field Operations
- All arithmetic in F_p (p=2^127−1)
- Use `Fp` struct (lo/hi u64 pair) - do **NOT** use standard modular arithmetic
- CRITICAL: `PCLMUL` instruction set support required (use `-march=native`)

### Text Encoding
- Messages split into 15-byte chunks → `Fp` (pack_15_bytes_to_fp)
- First ciphertext encodes length, rest encode payload
- 140-byte limit observed in bounty3 (11 ciphertexts total)

### Build Patterns
```bash
g++ -std=c++17 -O2 -march=native -I./include tests/YOUR_TEST.cpp
```
- **-march=native**: Required for PCLMUL optimizations (~3x speedup)
- **-O2**: Balances compilation speed vs runtime (O3 not necessary)
- **No extern deps**: Header-only crypto library

### Test Structure
Each test in `tests/` follows pattern:
1. Load/generate keys
2. Encrypt test vector
3. Perform ops (add/mul/text encode)
4. Decrypt and validate
5. Print metrics (timing, CTs generated)

## Attack Surface & Cryptanalysis Notes

### LPN Assumption
The security rests entirely on hardness of binary parity LPN:
- **Parameters**: m=8192 bits, n=4096 unknowns, τ=1/8 error rate
- Classical attacks: Gaussian elimination ~2^200 operations
- Quantum attacks: Grover's can reduce ~2^100
- **Known weaknesses explored in tests**:
  - `bounty_r2_attack.cpp`: R² leakage via edge pairs with opposite signs
  - `bounty3_test.cpp`: Structure of ciphertext (9 BASE layers) creates exploitable patterns

### Bounty Challenges
- **bounty3_data/**: Sealed message without secret key - tests structural attack resistance
- **bounty2_data/**: Homomorphic addition (known plaintext: 1+2=3)
- Intentionally left unsecured for CTF-style audit

## Common Developer Workflows

### Adding a New Homomorphic Operation
1. Implement in `include/pvac/ops/YOUR_OP.hpp`
2. Use `dec_value()` decryption framework as model
3. Add test in `tests/test_YOUR_OP.cpp`
4. Ensure noise growth is bounded (check depth warnings)

### Debugging Decryption Failures
- First: validate sk was loaded correctly (64-bit PRF key)
- Check `layer_R_cached()` visited all required layers
- Inspect `BitvecH` for syndrome computation consistency
- Use `PVAC_DBG=1 make test` for verbose layer trace

### Performance Profiling
- Timing instrumented via `prf_R()` and `fp_mul()` calls
- Output shows `impl=pclmul` confirming CPU support
- Target ~1ms per 140-byte encrypt on x86-64

### Creating New Test Files
Use bounty3_test.cpp as template:
- Save/load serialization (io:: and ser:: namespaces)
- Magic numbers: CT=0x66699666, SK=0x66666999, PK=0x06660666
- Always call `keygen()` before ops

## Integration Points

### External Files
- **params.json**: Human-readable Params copy (not loaded at runtime)
- **pk.bin**: Serialized PubKey (337 generators, 16384 H vectors)
- **sk.bin**: Serialized SecKey (PRF_k + lpn_s_bits)
- **.ct**: Ciphertext files (Cipher DAG + edges)

### Dependency Assumptions
- C++17 standard library only (no boost, no openssl)
- **Assumes system provides**: x86-64 CPU with PCLMUL (rdrand for CSPRNG)
- LPN solver must be external tool (not included)

## Key Gotchas

1. **Field Arithmetic Traps**:
   - Fp uses custom 127-bit prime, NOT standard modular reduction
   - `fp_mul()` uses PCLMUL - **never mix with stdlib%**
   - Hi bits must stay in [0, 2^64) range

2. **Serialization Format**:
   - Little-endian binary; Layer/Edge order matters
   - Missing sk.bin file doesn't fail load - decryption just returns garbage

3. **Depth & Noise**:
   - Plaintext recovered via R factors, not noise removal
   - Multi-level PROD rules increase decryption error (but still zero-error with sk)
   - `depth_hint` param in text encryption affects layer DAG shape

4. **Bounty3 Structure**:
   - No sk.bin provided - purely ciphertext-only challenge
   - Expected plaintext: "mnemonic: (12-word phrase), number: (value)"
   - Contains 11 ciphertexts total (1 length + 10 data blocks)

## Recommended Reading Order

1. **types.hpp** - understand Cipher/Layer/Edge layout
2. **field.hpp** - Fp arithmetic
3. **keygen.hpp** - how parameters are chosen
4. **encrypt.hpp** - plaintext→ciphertext transformation
5. **decrypt.hpp** - sk-dependent recovery
6. **bounty3_test.cpp** - end-to-end example

## Quick Reference

| Task | File | Entry Point |
|------|------|-------------|
| Understand types | `core/types.hpp` | `struct Cipher`, `struct Edge` |
| Field ops | `core/field.hpp` | `fp_mul()`, `fp_add()` |
| Encrypt value | `ops/encrypt.hpp` | `enc_value(pk, sk, plaintext)` |
| Decrypt value | `ops/decrypt.hpp` | `dec_value(pk, sk, cipher)` |
| Text encoding | `utils/text.hpp` | `enc_text()`, `dec_text()` |
| Homo ops | `ops/arithmetic.hpp` | `ct_add(pk, a, b)` |
| Key gen | `crypto/keygen.hpp` | `keygen(prm, pk, sk)` |
