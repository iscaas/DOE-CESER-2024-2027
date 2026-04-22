# Compiler
CC = gcc
CFLAGS = -Wall -O2 -lssl -lcrypto

# Targets
SERVER = server
CLIENT = client

# Directories
KEY_DIR = ./keys

# Default Target
all: $(SERVER) $(CLIENT)

# Build Client
$(CLIENT): client.c
	$(CC) client.c -o $(CLIENT) $(CFLAGS)

# Build Server
$(SERVER): server.c
	$(CC) server.c -o $(SERVER) $(CFLAGS)

# Generate Keys using the CA script
keys:
	@echo "[Makefile] Generating keys using CA..."
	@bash ca_generate_keys.sh

# Run Client
run-client: $(CLIENT) keys
	@echo "[Makefile] Running the client..."
	@cd "$(CURDIR)" && ./$(CLIENT)

# Run Server
run-server: $(SERVER) keys
	@echo "[Makefile] Running the server..."
	@cd "$(CURDIR)" && ./$(SERVER)

# Clean up generated files
clean:
	@echo "[Makefile] Cleaning up..."
	@rm -f $(SERVER) $(CLIENT)
	@rm -rf $(KEY_DIR)
