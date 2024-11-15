#include "aes.h"

// Implement the following functions:
unsigned char sbox[256];
unsigned char inv_sbox[256];

void aes_sbox_init();
void aes_inv_sbox_init();

void aes_add_round_key(unsigned char* state, const unsigned char* round_key);
void aes_sub_bytes(unsigned char* state);
void aes_inv_sub_bytes(unsigned char* state);
void aes_shift_rows(unsigned char* state);
void aes_inv_shift_rows(unsigned char* state);
void aes_mix_columns(unsigned char* state);
void aes_inv_mix_columns(unsigned char* state);

// Key Expansion
void aes_key_expansion(const unsigned char* key, unsigned char* round_keys, int key_size);

// Encryption
void aes_encrypt(const unsigned char* plaintext, unsigned char* ciphertext, const unsigned char* round_keys, int key_size);

// Decryption
void aes_decrypt(const unsigned char* ciphertext, unsigned char* plaintext, const unsigned char* round_keys, int key_size);