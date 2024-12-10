#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "aes.h"

// Cryptographically secure random number generation
void generate_secure_key(unsigned char *key, size_t key_length)
{
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom)
    {
        perror("Failed to open /dev/urandom");
        exit(1);
    }

    if (fread(key, 1, key_length, urandom) != key_length)
    {
        perror("Failed to read random bytes");
        fclose(urandom);
        exit(1);
    }

    fclose(urandom);
}

// Measure time in seconds
double measure_time(clock_t start, clock_t end)
{
    return ((double)(end - start)) / CLOCKS_PER_SEC;
}

// Read file
unsigned char *read_file(const char *filename, size_t *length)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        perror("Error opening file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *length = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *buffer = malloc(*length);
    if (!buffer)
    {
        perror("Memory allocation error");
        fclose(file);
        return NULL;
    }

    if (fread(buffer, 1, *length, file) != *length)
    {
        perror("File read error");
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);
    return buffer;
}

// Write file
int write_file(const char *filename, unsigned char *data, size_t length)
{
    FILE *file = fopen(filename, "wb");
    if (!file)
    {
        perror("Error writing file");
        return 0;
    }

    if (fwrite(data, 1, length, file) != length)
    {
        perror("File write error");
        fclose(file);
        return 0;
    }

    fclose(file);
    return 1;
}

void read_key(unsigned char *key, size_t key_length)
{

    // Ler a chave do arquivo
    size_t file_length;
    unsigned char *read_key = read_file("encryption_key.bin", &file_length);

    if (!read_key)
    {
        fprintf(stderr, "Failed to read key from file\n");
        exit(1);
    }

    if (file_length != key_length)
    {
        fprintf(stderr, "Key length mismatch: expected %zu, got %zu\n", key_length, file_length);
        free(read_key);
        exit(1);
    }

    memcpy(key, read_key, key_length);
    free(read_key);
}

int main(int argc, char *argv[])
{
    // Argument checking
    if (argc < 4)
    {
        fprintf(stderr, "Usage: %s <input_file> <output_file> <mode: encrypt|decrypt>\n", argv[0]);
        return 1;
    }

    const char *input_file = argv[1];
    const char *output_file = argv[2];
    const char *mode = argv[3];

    // Read input file
    size_t input_length;
    unsigned char *input_data = read_file(input_file, &input_length);
    if (!input_data)
    {
        return 1;
    }

    // Prepare for encryption/decryption
    size_t padded_length;
    unsigned char *padded_data;
    unsigned char key[16];
    unsigned char round_keys[176];
    unsigned char *output_data = NULL;

    clock_t start, end;
    start = clock();

    if (strcmp(mode, "encrypt") == 0)
    {
        // Key generation and expansion
        generate_secure_key(key, sizeof(key));
        aes_key_expansion(key, round_keys, 128);

        write_file("encryption_key.bin", key, sizeof(key));

        // Padding before encryption
        padded_data = add_padding(input_data, input_length, &padded_length);
        free(input_data);

        output_data = malloc(padded_length);
        if (!output_data)
        {
            perror("Memory allocation error for output");
            free(padded_data);
            return 1;
        }

        // Encrypt each block
        for (size_t i = 0; i < padded_length; i += AES_BLOCK_SIZE)
        {
            aes_encrypt(padded_data + i, output_data + i, round_keys, 128);
        }

        input_length = padded_length;

        free(padded_data);
    }
    if (strcmp(mode, "decrypt") == 0)
    {
        read_key(key, sizeof(key));
        output_data = malloc(input_length);
        aes_key_expansion(key, round_keys, 128);

        if (!output_data)
        {
            perror("Memory allocation error for output");
            free(input_data);
            return 1;
        }

        // Decrypt each block
        for (size_t i = 0; i < input_length; i += AES_BLOCK_SIZE)
        {
            aes_decrypt(input_data + i, output_data + i, round_keys, 128);
        }

        // Remove padding
        size_t original_length;
        unsigned char *temp = remove_padding(output_data, input_length, &original_length);

        free(output_data);  // Free the original buffer
        output_data = temp; // Use the de-padded buffer
        input_length = original_length;
    }
    else
    {
        fprintf(stderr, "Invalid mode: use 'encrypt' or 'decrypt'\n");
        free(input_data);
        return 1;
    }

    end = clock();

    // Write output file
    if (!write_file(output_file, output_data, input_length))
    {
        free(input_data);
        free(output_data);
        return 1;
    }

    // Print execution time
    printf("Total time (%s): %.6f seconds\n", mode, measure_time(start, end));

    // Free memory
    free(output_data);
    return 0;
}