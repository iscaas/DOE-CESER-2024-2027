// Helper function to print bytes as hex
void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Helper function to write binary key to file
int write_binary_key_to_file(const char* filename, const unsigned char* key_data, size_t key_len) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("Error opening file for writing");
        fprintf(stderr, "Filename: %s\n", filename);
        return -1;
    }
    size_t bytes_written = fwrite(key_data, 1, key_len, fp);
    fclose(fp);
    if (bytes_written != key_len) {
        fprintf(stderr, "Error writing key to %s (wrote %zu of %zu bytes)\n", filename, bytes_written, key_len);
        return -1;
    }
    printf("Successfully wrote binary key to %s\n", filename);
    return 0;
}

// Helper function to write key to file (hex encoded string)
int write_hex_key_to_file(const char* filename, const unsigned char* key_data, size_t key_len) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        perror("Error opening file for writing");
        fprintf(stderr, "Filename: %s\n", filename);
        return -1;
    }
    char *hex_string = (char *)sodium_malloc(key_len * 2 + 1);
    if (hex_string == NULL) {
        fprintf(stderr, "Failed to allocate memory for hex string for %s.\n", filename);
        fclose(fp);
        return -1;
    }
    if (sodium_bin2hex(hex_string, key_len * 2 + 1, key_data, key_len) == NULL) {
        fprintf(stderr, "sodium_bin2hex failed for %s.\n", filename);
        sodium_free(hex_string);
        fclose(fp);
        return -1;
    }
    fprintf(fp, "%s\n", hex_string);
    sodium_free(hex_string);
    fclose(fp);
    printf("Successfully wrote hex key to %s\n", filename);
    return 0;
}
