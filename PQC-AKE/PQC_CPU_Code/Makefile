CC = gcc
CFLAGS = -O2 -Wall
LIBS = -loqs -lcrypto

SERVER = server
CLIENT = client
KEYGEN = pqc_keygen

SERVER_SRC = server.c
CLIENT_SRC = client.c
KEYGEN_SRC = pqc_keygen.c

KEY_DIR = ./keys

KEY_FILES = \
	$(KEY_DIR)/ca_falcon_public.key \
	$(KEY_DIR)/ca_falcon_private.key \
	$(KEY_DIR)/gsm_falcon_private.key \
	$(KEY_DIR)/sgn_falcon_private.key \
	$(KEY_DIR)/gsm_cert.bin \
	$(KEY_DIR)/sgn_cert.bin

.PHONY: all clean keys force-keys run-server run-client

all: $(SERVER) $(CLIENT) $(KEYGEN)

$(SERVER): $(SERVER_SRC)
	$(CC) $(CFLAGS) $(SERVER_SRC) -o $(SERVER) $(LIBS)

$(CLIENT): $(CLIENT_SRC)
	$(CC) $(CFLAGS) $(CLIENT_SRC) -o $(CLIENT) $(LIBS)

$(KEYGEN): $(KEYGEN_SRC)
	$(CC) $(CFLAGS) $(KEYGEN_SRC) -o $(KEYGEN) $(LIBS)

keys: $(KEYGEN)
	@mkdir -p $(KEY_DIR)
	@if [ ! -f "$(KEY_DIR)/ca_falcon_public.key" ] || \
	      [ ! -f "$(KEY_DIR)/ca_falcon_private.key" ] || \
	      [ ! -f "$(KEY_DIR)/gsm_falcon_private.key" ] || \
	      [ ! -f "$(KEY_DIR)/sgn_falcon_private.key" ] || \
	      [ ! -f "$(KEY_DIR)/gsm_cert.bin" ] || \
	      [ ! -f "$(KEY_DIR)/sgn_cert.bin" ]; then \
		echo "[Makefile] Generating PQC keys/certs into ./keys ..."; \
		./$(KEYGEN); \
	else \
		echo "[Makefile] PQC keys/certs already exist."; \
	fi

force-keys: $(KEYGEN)
	@mkdir -p $(KEY_DIR)
	@echo "[Makefile] Force-regenerating PQC keys/certs into ./keys ..."
	@rm -f $(KEY_FILES)
	@./$(KEYGEN)

run-server: keys $(SERVER)
	@./$(SERVER)

run-client: keys $(CLIENT)
	@./$(CLIENT)

clean:
	rm -f $(SERVER) $(CLIENT) $(KEYGEN)
	rm -rf $(KEY_DIR)