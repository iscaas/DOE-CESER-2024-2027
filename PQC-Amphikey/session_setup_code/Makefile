CC  = gcc
CXX = g++

# -DPC is REQUIRED by FELICS: RAM_DATA_BYTE and related target macros only
# expand correctly when PC is defined. Without it, tag_verification.c:48
# fails with "expected initializer before 'generated_tag'".
CFLAGS   = -Wall -Wextra -O2 -DPC

# C++ flags for MeteringSDK targets:
#   -DPC           : same FELICS RAM_DATA_BYTE fix as C targets
#   -D__linux__    : required by C12Adapter / MeteringSDK platform headers
#   -fpermissive   : suppresses C→C++ implicit pointer-cast warnings in
#                    PQClean/fips202.c and Raccoon util (void* → typed ptr)
CXXFLAGS = -fpermissive -Wall -Wextra -O2 -DPC -D__linux__

# ── Base paths ────────────────────────────────────────────────────────────────
HOME         := $(shell echo ~)
RACCOON_BASE  = $(HOME)/raccoon/ref-c
PQCLEAN_BASE  = $(RACCOON_BASE)/PQClean

# Ascon-128 (NIST LWCA standard) — used by plain-C C12.22 network tests
ASCON_BASE    = $(RACCOON_BASE)/ascon-c-main

# ACORN-128 inside the FELICS benchmark framework.
# Full path confirmed from build log:
#   ~/raccoon/ref-c/FELICS-master/authenticated_ciphers/source/
#              ciphers/ACORN_1_128_128_293_128_v02/source/
FELICS_BASE   = $(RACCOON_BASE)/FELICS-master/authenticated_ciphers/source
ACORN_CIPHER  = $(FELICS_BASE)/ciphers/ACORN_1_128_128_293_128_v02/source
ACORN_COMMON  = $(FELICS_BASE)/common

# C12Adapter MeteringSDK — used by hybrid_sender/receiver_c1222.cpp only
C12ADAPTER_BASE  = $(HOME)/C12Adapter
C12ADAPTER_SRC   = $(C12ADAPTER_BASE)/src/MeteringSDK
C12ADAPTER_BUILD = $(C12ADAPTER_BASE)/build/MeteringSDK
C12ADAPTER_LIB   = $(C12ADAPTER_BASE)/build/lib

# ── Raccoon DSA sources ───────────────────────────────────────────────────────
RACCOON_SRC = \
    $(RACCOON_BASE)/racc_api.c     \
    $(RACCOON_BASE)/racc_core.c    \
    $(RACCOON_BASE)/racc_serial.c  \
    $(RACCOON_BASE)/polyr.c        \
    $(RACCOON_BASE)/ntt32.c        \
    $(RACCOON_BASE)/ntt64.c        \
    $(RACCOON_BASE)/mask_random.c  \
    $(RACCOON_BASE)/xof_sample.c

# Raccoon utility / RNG (NIST DRBG, Keccak, SHA-3)
UTIL_SRC = \
    $(RACCOON_BASE)/util/nist_random.c  \
    $(RACCOON_BASE)/util/keccakf1600.c  \
    $(RACCOON_BASE)/util/sha3_t.c       \
    $(RACCOON_BASE)/util/ct_util.c      \
    $(RACCOON_BASE)/util/test_aes1kt.c

# ── ML-KEM-768 (PQClean) ─────────────────────────────────────────────────────
PQCLEAN_SRC = $(PQCLEAN_BASE)/common/fips202.c
MLKEM_LIB   = $(PQCLEAN_BASE)/crypto_kem/ml-kem-768/clean/libml-kem-768_clean.a

# ── ACORN-128 (FELICS) sources ────────────────────────────────────────────────
# FELICS does NOT have a monolithic cipher.c — every operation is a separate
# file. All must be listed. tag_verification.c lives in the common/ directory.
#
# FIX for tag_verification.c:48 error:
#   "expected initializer before 'generated_tag'"
#   Root cause: RAM_DATA_BYTE was undefined (expands only with -DPC).
#   Solution: -DPC in CFLAGS / CXXFLAGS above resolves this entirely.
ACORN_SRC = \
    $(ACORN_CIPHER)/finalize.c                \
    $(ACORN_CIPHER)/initialize.c              \
    $(ACORN_CIPHER)/padding.c                 \
    $(ACORN_CIPHER)/permute.c                 \
    $(ACORN_CIPHER)/process_associated_data.c \
    $(ACORN_CIPHER)/process_ciphertext.c      \
    $(ACORN_CIPHER)/process_plaintext.c       \
    $(ACORN_CIPHER)/tag_generation.c          \
    $(ACORN_COMMON)/tag_verification.c

# FELICS size constants — must match ACORN-128 parameters
ACORN_CFLAGS = -DTAG_SIZE=16 -DKEY_SIZE=16 -DNONCE_SIZE=16

# ── Ascon-128 (NIST LWCA one-shot API) ───────────────────────────────────────
ASCON_SRC = $(ASCON_BASE)/crypto_aead/asconaead128/ref/aead.c

# ── ANSI C12.22 plain-C library sources ──────────────────────────────────────
C1222_LIB_SRC = \
    c12222/ansi_c1222.c  \
    c12222/ansi_c1218.c  \
    c12222/ansi_tblmgr.c \
    c12222/aes.c         \
    c12222/eax.c         \
    c12222/crc.c         \
    c12222/table00.c     \
    c12222/table03.c     \
    c12222/table05.c

# ── Include paths ─────────────────────────────────────────────────────────────
# Shared (all targets)
INC_COMMON = \
    -I.                                             \
    -I$(RACCOON_BASE)                               \
    -I$(RACCOON_BASE)/inc                           \
    -I$(RACCOON_BASE)/util                          \
    -I$(PQCLEAN_BASE)/common                        \
    -I$(PQCLEAN_BASE)/crypto_kem/ml-kem-768/clean  \
    -I$(ASCON_BASE)/crypto_aead/asconaead128/ref    \
    -I$(ASCON_BASE)/tests

# AmphiKey auth mode standalone (adds ACORN/FELICS headers)
INC_AUTH = \
    $(INC_COMMON)      \
    -I$(ACORN_CIPHER)  \
    -I$(ACORN_COMMON)

# ANSI C12.22 plain-C apps (adds Ascon + local c12222 headers)
INC_C1222 = \
    $(INC_COMMON)                                \
    -Ic12222                                     \
    -I$(ASCON_BASE)/crypto_aead/asconaead128/ref \
    -I$(ASCON_BASE)/tests

# ANSI C12.22 C++ apps (ACORN/FELICS + MeteringSDK on top of INC_AUTH)
INC_C1222_CXX = \
    $(INC_AUTH)           \
    -I$(C12ADAPTER_SRC)   \
    -I$(C12ADAPTER_BUILD)

# ── Dependency groups (reusable) ──────────────────────────────────────────────
# A: ML-KEM + libsodium only (Deniable Mode + bench — no Raccoon, no AEAD)
DEPS_DENY = $(PQCLEAN_SRC) $(MLKEM_LIB) -lsodium -lm

# B: Raccoon + ML-KEM + ACORN + libsodium (AmphiKey Auth Mode standalone)
DEPS_AUTH = $(RACCOON_SRC) $(UTIL_SRC) $(PQCLEAN_SRC) $(ACORN_SRC) $(MLKEM_LIB) -lsodium -lm

# C: Raccoon + ML-KEM + Ascon + C12.22 lib + libsodium (plain-C C12.22 apps)
DEPS_C1222 = $(C1222_LIB_SRC) $(ASCON_SRC) $(RACCOON_SRC) $(UTIL_SRC) $(PQCLEAN_SRC) $(MLKEM_LIB) -lsodium -lm

# D: Raccoon + ML-KEM + ACORN + MeteringSDK (C++ C12.22 apps)
DEPS_C1222_CXX = \
    $(RACCOON_SRC) $(UTIL_SRC) $(PQCLEAN_SRC) $(ACORN_SRC) $(MLKEM_LIB) \
    -L$(C12ADAPTER_LIB) -lMCOM -lMCORE -lsodium -lm -lpthread

# =============================================================================
# Top-level targets
# =============================================================================
.PHONY: all protocol bench c1222 clean help

all: protocol bench c1222

# AmphiKey protocol executables
protocol: auth_server auth_client deny_server deny_client

# Isolated benchmark executables
bench: deny_sender_bench deny_receiver_bench

# ANSI C12.22 network test executables (plain-C + C++ MeteringSDK)
c1222: c1222_hybrid_server c1222_hybrid_client sender_c1222 receiver_c1222

# =============================================================================
# AmphiKey Authenticated Mode (Section IV-B)
# =============================================================================

# Server: signs Server Hello (SHs), decapsulates, verifies sigc, derives ksh
auth_server: hybrid_bench_main.c
	$(CC) $(CFLAGS) $(ACORN_CFLAGS) $(INC_AUTH) -o $@ $< $(DEPS_AUTH)

# Client: verifies sigs, encapsulates via DHKEM+MLKEM, signs sigc, derives ksh
auth_client: receiver_protocol_main.c
	$(CC) $(CFLAGS) $(ACORN_CFLAGS) $(INC_AUTH) -o $@ $< $(DEPS_AUTH)

# =============================================================================
# AmphiKey Deniable Mode (Section IV-C)
# =============================================================================

# Server: generates nonce rs (Server Hello), decapsulates, verifies HMAC tag
deny_server: denyreceiver_main.c
	$(CC) $(CFLAGS) $(INC_COMMON) -o $@ $< $(DEPS_DENY)

# Client: reads rs, encapsulates via DHKEM+MLKEM, computes HMAC tag
deny_client: denysender_main.c
	$(CC) $(CFLAGS) $(INC_COMMON) -o $@ $< $(DEPS_DENY)

# =============================================================================
# Isolated per-operation benchmarks (1000-iteration averages, ns + CPU cycles)
# =============================================================================

deny_sender_bench: denysender_bench.c
	$(CC) $(CFLAGS) $(INC_COMMON) -o $@ $< $(DEPS_DENY)

deny_receiver_bench: denyreceiver_bench.c
	$(CC) $(CFLAGS) $(INC_COMMON) -o $@ $< $(DEPS_DENY)

# =============================================================================
# Deliverable 4.1 — Crypto benchmark
#   Ciphers: AES-128/256-CBC+HMAC, AES-128-GCM, Ascon-128, ChaCha20-Poly1305,
#            HMAC-SHA256 across six smart-meter payload sizes.
#
# Dependencies:
#   - Ascon-128 source  (ASCON_SRC)       — crypto_aead_encrypt/decrypt
#   - OpenSSL           (-lssl -lcrypto)  — EVP_*, ERR_*, OPENSSL_init_crypto
#   - libsodium         (-lsodium)        — ChaCha20-Poly1305, HMAC-SHA256,
#                                           randombytes_buf, sodium_init
#
# NOTE: $(MLKEM_LIB) is intentionally omitted — crypto_bench.c has no ML-KEM
# calls and linking the static archive is unnecessary.
#
# Library ordering: source/object files MUST precede -l flags so the linker
# resolves symbols correctly (left-to-right single-pass).
# =============================================================================

# crypto_bench is a real file target — do NOT list it under .PHONY.
crypto_bench: crypto_bench.c $(ASCON_SRC)
	$(CC) $(CFLAGS) $(INC_COMMON) -o $@ $< $(ASCON_SRC) -lssl -lcrypto -lsodium -lm

# =============================================================================
# ANSI C12.22 plain-C full network tests (TCP, raw socket, Ascon AEAD)
# =============================================================================

c1222_hybrid_server: c1222_hybrid_server_final.c
	$(CC) $(CFLAGS) $(INC_C1222) -o $@ $< $(DEPS_C1222)

c1222_hybrid_client: c1222_hybrid_client1.c
	$(CC) $(CFLAGS) $(INC_C1222) -o $@ $< $(DEPS_C1222)

# =============================================================================
# ANSI C12.22 C++ MeteringSDK tests (MProtocolC1222, MChannelSocket)
#
# Fixes applied to source files:
#   hybrid_sender_c1222.cpp:78   MByteString(unsigned char*, size_t)
#     → MByteString(reinterpret_cast<const char*>(payload.data()), payload.size())
#     Reason: MByteString is std::basic_string<char>; needs explicit char* cast.
#
#   hybrid_sender_c1222.cpp:81   protocol.Write(table_id, data)
#     → protocol.TableWrite(table_id, data)
#     Reason: MProtocolC1222 exposes TableRead/TableWrite, not Read/Write.
#
#   hybrid_sender_c1222.cpp:86   e.GetWhat()
#   hybrid_receiver_c1222.cpp    e.GetWhat()
#     → e.what()
#     Reason: MException inherits std::exception; the method is what().
#
#   hybrid_receiver_c1222.cpp    protocol.Read(data, table_id)
#     → protocol.TableRead(data, table_id)
#     Reason: same as TableWrite above.
#
#   hybrid_receiver_c1222.cpp    received_data.IsEmpty()
#     → received_data.empty()
#     Reason: MByteString is std::basic_string<char>; STL method is empty().
# =============================================================================

sender_c1222: hybrid_sender_c1222.cpp
	$(CXX) $(CXXFLAGS) $(ACORN_CFLAGS) $(INC_C1222_CXX) -o $@ $< $(DEPS_C1222_CXX)

receiver_c1222: hybrid_receiver_c1222.cpp
	$(CXX) $(CXXFLAGS) $(ACORN_CFLAGS) $(INC_C1222_CXX) -o $@ $< $(DEPS_C1222_CXX)

# =============================================================================
# Networked AmphiKey Authenticated Mode
# =============================================================================
.PHONY: net run_net

net: net_auth_server net_auth_client

net_auth_server: net_auth_server.c
	$(CC) $(CFLAGS) $(ACORN_CFLAGS) $(INC_AUTH) -o $@ $< $(DEPS_AUTH)

net_auth_client: net_auth_client.c
	$(CC) $(CFLAGS) $(ACORN_CFLAGS) $(INC_AUTH) -o $@ $< $(DEPS_AUTH)

# =============================================================================
# Convenience run targets
# =============================================================================
.PHONY: run_deny run_auth

run_deny: deny_server deny_client
	@echo ""
	@echo "=== AmphiKey Deniable Mode ==="
	@echo "[Step 1] Server Hello — generating session nonce rs..."
	./deny_server
	@echo ""
	@echo "[Step 2] Client encapsulation + HMAC tag..."
	./deny_client
	@echo ""
	@echo "[Step 3] Server decapsulation + tag verification + ksh derivation..."
	./deny_server

run_auth: auth_server auth_client
	@echo ""
	@echo "=== AmphiKey Authenticated Mode ==="
	@echo "[Step 1] Server Hello — signing SHs with Raccoon..."
	./auth_server
	@echo ""
	@echo "[Step 2] Client — verifying sigs, encapsulating, signing sigc..."
	./auth_client
	@echo ""
	@echo "[Step 3] Server — verifying sigc, decapsulating, deriving ksh..."
	./auth_server

# =============================================================================
# Utility
# =============================================================================
clean:
	rm -f auth_server auth_client deny_server deny_client \
	      deny_sender_bench deny_receiver_bench \
	      c1222_hybrid_server c1222_hybrid_client \
	      sender_c1222 receiver_c1222 \
	      net_auth_server net_auth_client \
	      crypto_bench \
	      *.o \
	      server_hello.bin server_sigs.sig \
	      server_nonce_rs.bin \
	      c_data_to_receiver.bin tag_to_receiver.bin \
	      client_encap_c.bin client_sigc.sig \
	      server_response_nonce.bin server_response_ct.bin

help:
	@echo ""
	@echo "AmphiKey — DOE Deliverable 2.2"
	@echo ""
	@echo "Build targets:"
	@echo "  make all                  Build everything"
	@echo "  make protocol             Auth + Deniable Mode executables"
	@echo "  make bench                Isolated benchmark executables"
	@echo "  make c1222                ANSI C12.22 network test executables"
	@echo "  make crypto_bench         Deliverable 4.1 cipher comparison benchmark"
	@echo ""
	@echo "Protocol executables:"
	@echo "  auth_server   hybrid_bench_main.c       Auth Mode server (sign SHs, decap)"
	@echo "  auth_client   receiver_protocol_main.c  Auth Mode client (verify, encap, sign)"
	@echo "  deny_server   denyreceiver_main.c       Deniable Mode server (nonce, decap, verify)"
	@echo "  deny_client   denysender_main.c         Deniable Mode client (encap, tag)"
	@echo ""
	@echo "Benchmark executables:"
	@echo "  deny_sender_bench    Per-operation timing: Deniable Mode sender"
	@echo "  deny_receiver_bench  Per-operation timing: Deniable Mode receiver"
	@echo "  crypto_bench         Cipher benchmark: AES-CBC/GCM, Ascon-128,"
	@echo "                       ChaCha20-Poly1305, HMAC-SHA256 (6 payload sizes)"
	@echo ""
	@echo "C12.22 executables:"
	@echo "  c1222_hybrid_server  Plain-C TCP server (Ascon AEAD)"
	@echo "  c1222_hybrid_client  Plain-C TCP client (Ascon AEAD)"
	@echo "  sender_c1222         C++ MeteringSDK sender  (MProtocolC1222)"
	@echo "  receiver_c1222       C++ MeteringSDK receiver (MProtocolC1222)"
	@echo ""
	@echo "Networked AmphiKey:"
	@echo "  net_auth_server      Networked Auth Mode server"
	@echo "  net_auth_client      Networked Auth Mode client"
	@echo ""
	@echo "Workflow shortcuts:"
	@echo "  make run_deny         Run full Deniable Mode 3-step protocol"
	@echo "  make run_auth         Run full Auth Mode 3-step protocol"
	@echo ""
	@echo "  make clean            Remove all build artifacts and protocol files"
	@echo ""
