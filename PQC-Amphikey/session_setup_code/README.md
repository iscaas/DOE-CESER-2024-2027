# AmphiKey — PQC Hybrid AKEM Implementation

Implements both protocol modes from the AmphiKey paper using ML-KEM-768 (NIST PQC), X25519-DHKEM, Raccoon DSA, and Ascon-128 (NIST LWCA).

---

## Dependencies

- libsodium (`sudo apt install libsodium-dev`)
- raccoon/ref-c — Raccoon DSA + ML-KEM-768 + Ascon-128 (expected at `~/raccoon/ref-c/`)
- C12Adapter — MeteringSDK for ANSI C12.22 TCP (expected at `~/C12Adapter/`)

---

## Build

```bash
cd ~/session_setup_code

# Auth mode + bench programs
make auth_server auth_client deny_sender_bench deny_receiver_bench

# C12.22 Deniable Mode network programs
make sender_c1222 receiver_c1222
```

---

## Authenticated Mode (Table I Steps 1–3)

```bash
# Clean state before each full run
rm -f client_encap_c.bin client_sigc.sig client_raccoon_pk.key client_ksh.bin
rm -f server_hello.bin server_sigs.sig server_mlkem_sk.key server_mlkem_pk.key
rm -f server_x25519_sk.hex server_x25519_pk.hex server_response_nonce.bin server_response_ct.bin

./auth_server   # Step 1: KeyGen + Raccoon.Sign(SHs)
./auth_client   # Step 2: Verify sigs, ML-KEM.Enc, DHKEM.Enc, Raccoon.Sign(sigc), HKDF ksh
./auth_server   # Step 3: Raccoon.Verify(sigc), ML-KEM.Dec, DHKEM.Dec, HKDF ksh, Ascon.Enc
./auth_client   # Post-handshake: Ascon-128 AEAD Decrypt (auto-detects, skips Step 2)
```

---

## Deniable Mode — C12.22 Network (live TCP)

```bash
# Terminal 1
./receiver_c1222 1153

# Terminal 2
./sender_c1222 127.0.0.1 1153
```

---

## Deniable Mode — Isolated Benchmarks (1000-iter averages)

```bash
./deny_sender_bench     # generates bench_*.bin files
./deny_receiver_bench   # reads bench_*.bin — run sender first
```

---

## Key Files

| File | Purpose |
|---|---|
| `hybrid_bench_main.c` | Auth server — Table II KeyGen + Steps 1 & 3 |
| `receiver_protocol_main.c` | Auth client — Step 2 + post-handshake decrypt |
| `denysender_bench.c` | Deniable Mode sender benchmarks |
| `denyreceiver_bench.c` | Deniable Mode receiver benchmarks |
| `hybrid_sender_c1222.cpp` | C12.22 Deniable Mode sender (TCP) |
| `hybrid_receiver_c1222.cpp` | C12.22 Deniable Mode receiver (TCP) |
| `GNUmakefile` | Full project build |
| `makefile` | C12.22 session_setup_code build (lowercase, takes priority) |

---

## Notes

- `auth_server` auto-detects step: runs Step 1 if `client_encap_c.bin` absent, Step 3 if present.
- `auth_client` auto-detects: runs Step 2 if `server_response_nonce.bin` absent, post-handshake decrypt only if both `server_response_nonce.bin` and `client_ksh.bin` exist.
- Raccoon long-term keys (`server_raccoon_sk/pk.key`) are reused across runs. Delete to regenerate.
- All AEAD uses **Ascon-128** (NIST LWCA). 
