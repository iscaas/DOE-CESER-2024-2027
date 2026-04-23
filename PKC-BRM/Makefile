# Compiler and Flags
CC = gcc
CFLAGS = -Wall -O2
LIBS = -lssl -lcrypto

# Directories
KEY_DIR = ./keys
CERT_DIR = ./certs

# Targets
SERVER = server
CLIENT = client
COMMON_SRC = verify_certificate.c ascon.c
COMMON_OBJ = verify_certificate.o ascon.o

# Default Target
all: $(SERVER) $(CLIENT)

# Object files
%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

# Build Client
$(CLIENT): client.c $(COMMON_OBJ)
	$(CC) client.c $(COMMON_OBJ) -o $(CLIENT) $(CFLAGS) $(LIBS)

# Build Server
$(SERVER): server.c $(COMMON_OBJ)
	$(CC) server.c $(COMMON_OBJ) -o $(SERVER) $(CFLAGS) $(LIBS)

# Generate Keys using the CA script
keys:
	@echo "[Makefile] Generating keys using CA..."
	@bash ca_generate_keys.sh

# Run Client
run-client: $(CLIENT) keys
	@echo "[Makefile] Running the client..."
	@./$(CLIENT)

# Run Server
run-server: $(SERVER) keys
	@echo "[Makefile] Running the server..."
	@./$(SERVER)

# Clean up generated files
clean:
	@echo "[Makefile] Cleaning up..."
	@rm -f $(SERVER) $(CLIENT) *.o
	@rm -rf $(KEY_DIR) $(CERT_DIR)
	@rm -f *.csr *.srl
