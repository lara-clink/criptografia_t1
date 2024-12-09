#ifndef AES_H
#define AES_H

#define AES_BLOCK_SIZE 16             // 128-bit blocks
#define AES_KEY_SIZES {128, 192, 256} // Supported key sizes

unsigned char *add_padding(unsigned char *input, size_t input_length, size_t *padded_length);
unsigned char *remove_padding(unsigned char *input, size_t input_length, size_t *output_length);
void aes_key_expansion(const unsigned char *key, unsigned char *round_keys, int key_size);
void aes_encrypt(const unsigned char *plaintext, unsigned char *ciphertext, const unsigned char *round_keys, int key_size);
void aes_decrypt(unsigned char *input, unsigned char *output, const unsigned char *key, int key_size);

#endif