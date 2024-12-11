// Alunos: Lara Ricalde Machado Clink e Vinicius Oliveira dos Santos

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>
#include "aes.h"

// Tabela de substituição (S-Box) padrão do AES
static unsigned char s_box[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static unsigned char inv_s_box[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

// RCon (constantes de rotação) para a expansão da chave
static const unsigned char rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

// Substitui um byte usando a S-Box
static unsigned char sub_byte(unsigned char byte)
{
    return s_box[byte];
}

// Realiza uma rotação para a esquerda de 1 byte em uma palavra de 4 bytes
static void rotate_word(unsigned char *word)
{
    unsigned char temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

void aes_key_expansion(const unsigned char *key, unsigned char *round_keys, int key_size)
{
    int nk = key_size / 32; // Número de colunas na chave original
    int nb = 4;             // Número de colunas no estado
    int nr = nk + 6;        // Número de rodadas

    memcpy(round_keys, key, nk * 4);

    unsigned char temp[4];
    for (int i = nk; i < nb * (nr + 1); i++)
    {
        memcpy(temp, &round_keys[(i - 1) * 4], 4);

        if (i % nk == 0)
        {
            rotate_word(temp);
            for (int j = 0; j < 4; j++)
            {
                temp[j] = sub_byte(temp[j]);
            }
            temp[0] ^= rcon[i / nk - 1];
        }
        else if (nk > 6 && i % nk == 4)
        {
            for (int j = 0; j < 4; j++)
            {
                temp[j] = sub_byte(temp[j]);
            }
        }

        for (int j = 0; j < 4; j++)
        {
            round_keys[i * 4 + j] = round_keys[(i - nk) * 4 + j] ^ temp[j];
        }
    }
}

static void add_round_key(unsigned char *state, const unsigned char *round_key)
{
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        state[i] ^= round_key[i];
    }
}

static void sub_bytes(unsigned char *state, size_t length)
{
    if (length != 16)
    {
        fprintf(stderr, "Erro: o estado deve conter exatamente 16 bytes.\n");
        return;
    }
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        state[i] = sub_byte(state[i]);
    }
}

static void shift_rows(unsigned char *state)
{
    unsigned char temp;
    // Segunda linha
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Terceira linha
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Quarta linha
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

static unsigned char gmul(unsigned char a, unsigned char b)
{
    unsigned char p = 0;
    for (int i = 0; i < 8; i++)
    {
        if (b & 1)
            p ^= a;

        int hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set)
            a ^= 0x1B;

        b >>= 1;
    }
    return p;
}

static void mix_columns(unsigned char *state)
{
    for (int i = 0; i < 4; i++)
    {
        unsigned char *col = state + i * 4;
        unsigned char a = col[0], b = col[1], c = col[2], d = col[3];

        col[0] = gmul(a, 2) ^ gmul(b, 3) ^ c ^ d;
        col[1] = a ^ gmul(b, 2) ^ gmul(c, 3) ^ d;
        col[2] = a ^ b ^ gmul(c, 2) ^ gmul(d, 3);
        col[3] = gmul(a, 3) ^ b ^ c ^ gmul(d, 2);
    }
}

unsigned char *add_padding(const unsigned char *input, size_t input_length, size_t *padded_length)
{
    const size_t block_size = 16;

    if (!input || !padded_length)
    {
        fprintf(stderr, "Entrada inválida para adicionar padding\n");
        exit(1);
    }

    if (input_length > SIZE_MAX - block_size)
    {
        fprintf(stderr, "Tamanho de entrada muito grande para adicionar padding\n");
        exit(1);
    }

    size_t padding = block_size - (input_length % block_size);
    if (padding == 0)
        padding = block_size;

    *padded_length = input_length + padding;

    unsigned char *padded_data = malloc(*padded_length);
    if (!padded_data)
    {
        perror("Erro ao alocar memória para padding");
        exit(1);
    }

    memcpy(padded_data, input, input_length);
    memset(padded_data + input_length, padding, padding);

    return padded_data;
}

unsigned char *remove_padding(unsigned char *data, size_t input_length, size_t *original_length)
{
    if (input_length == 0)
        return NULL;

    unsigned char padding_value = data[input_length - 1];

    if (padding_value == 0 || padding_value > AES_BLOCK_SIZE)
    {
        fprintf(stderr, "Erro: padding inválido (%d). input_length: %zu\n", padding_value, input_length);
        return NULL;
    }

    for (size_t i = input_length - padding_value; i < input_length; i++)
    {
        if (data[i] != padding_value)
        {
            fprintf(stderr, "Erro: padding inconsistente\n");
            return NULL;
        }
    }

    *original_length = input_length - padding_value;
    unsigned char *result = malloc(*original_length);
    if (!result)
    {
        perror("Erro de alocação de memória");
        return NULL;
    }

    memcpy(result, data, *original_length);
    return result;
}

void aes_encrypt(const unsigned char *plaintext, unsigned char *ciphertext, const unsigned char *round_keys, int key_size)
{
    unsigned char state[AES_BLOCK_SIZE];
    memcpy(state, plaintext, AES_BLOCK_SIZE);

    int nr = key_size / 32 + 6;
    add_round_key(state, round_keys);

    for (int round = 1; round < nr; round++)
    {
        sub_bytes(state, sizeof(state));
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys + round * AES_BLOCK_SIZE);
    }

    sub_bytes(state, sizeof(state));
    shift_rows(state);
    add_round_key(state, round_keys + nr * AES_BLOCK_SIZE);

    memcpy(ciphertext, state, AES_BLOCK_SIZE);
}

static unsigned char inv_sub_byte(unsigned char byte, unsigned char inv_s_box[256])
{
    return inv_s_box[byte];
}

void inv_sub_bytes(unsigned char *state, size_t length, unsigned char inv_s_box[256])
{
    if (length != 16)
    {
        fprintf(stderr, "Erro: o estado deve conter exatamente 16 bytes.\n");
        return;
    }

    for (size_t i = 0; i < 16; i++)
    {
        state[i] = inv_sub_byte(state[i], inv_s_box);
    }
}

void inv_shift_rows(unsigned char *state)
{
    unsigned char temp;

    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = state[3];
    state[3] = temp;
}

static void inv_mix_columns(unsigned char *state)
{
    for (int i = 0; i < 4; i++)
    {
        unsigned char *col = state + i * 4;
        unsigned char a = col[0], b = col[1], c = col[2], d = col[3];

        col[0] = gmul(a, 0x0E) ^ gmul(b, 0x0B) ^ gmul(c, 0x0D) ^ gmul(d, 0x09);
        col[1] = gmul(a, 0x09) ^ gmul(b, 0x0E) ^ gmul(c, 0x0B) ^ gmul(d, 0x0D);
        col[2] = gmul(a, 0x0D) ^ gmul(b, 0x09) ^ gmul(c, 0x0E) ^ gmul(d, 0x0B);
        col[3] = gmul(a, 0x0B) ^ gmul(b, 0x0D) ^ gmul(c, 0x09) ^ gmul(d, 0x0E);
    }
}

void aes_decrypt(unsigned char *ciphertext, unsigned char *plaintext, const unsigned char *round_keys, int key_size)
{
    unsigned char state[AES_BLOCK_SIZE];
    memcpy(state, ciphertext, AES_BLOCK_SIZE);

    int nr = key_size / 32 + 6;

    // testa inv s box
    for (int i = 0; i < 256; i++)
    {
        if (s_box[inv_s_box[i]] != i)
        {
            fprintf(stderr, "Erro: inv_s_box não é o inverso de s_box\n");
            return;
        }
    }
    add_round_key(state, round_keys + nr * AES_BLOCK_SIZE);

    inv_shift_rows(state);

    inv_sub_bytes(state, sizeof(state), inv_s_box);

    for (int round = nr - 1; round > 0; round--)
    {
        add_round_key(state, round_keys + round * AES_BLOCK_SIZE);

        inv_mix_columns(state);

        inv_shift_rows(state);

        inv_sub_bytes(state, sizeof(state), inv_s_box);
    }

    add_round_key(state, round_keys);

    memcpy(plaintext, state, AES_BLOCK_SIZE);
}