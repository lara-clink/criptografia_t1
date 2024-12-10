#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include "aes.h"

// Tabela de substituição (S-Box) padrão do AES
static const unsigned char s_box[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D,
    0x0F, 0xB0, 0x54, 0xBB, 0x16};

static const unsigned char inv_s_box[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};

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

// Expande a chave inicial para gerar as chaves de rodada
void aes_key_expansion(const unsigned char *key, unsigned char *round_keys, int key_size)
{
    int nk = key_size / 32; // Número de colunas na chave original
    int nb = 4;             // Número de colunas no estado
    int nr = nk + 6;        // Número de rodadas

    // Copiar chave inicial para o início das chaves de rodada
    memcpy(round_keys, key, nk * 4);

    unsigned char temp[4];
    for (int i = nk; i < nb * (nr + 1); i++)
    {
        memcpy(temp, &round_keys[(i - 1) * 4], 4);

        if (i % nk == 0)
        {
            rotate_word(temp); // Rotação
            for (int j = 0; j < 4; j++)
            {
                temp[j] = sub_byte(temp[j]); // Substituição
            }
            temp[0] ^= rcon[i / nk - 1]; // XOR com RCon
        }
        else if (nk > 6 && i % nk == 4)
        {
            for (int j = 0; j < 4; j++)
            {
                temp[j] = sub_byte(temp[j]);
            }
        }

        // XOR com a palavra anterior
        for (int j = 0; j < 4; j++)
        {
            round_keys[i * 4 + j] = round_keys[(i - nk) * 4 + j] ^ temp[j];
        }
    }
}

// Adiciona a chave de rodada ao estado (XOR)
static void add_round_key(unsigned char *state, const unsigned char *round_key)
{
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        state[i] ^= round_key[i];
    }
}

// Substitui todos os bytes no estado usando a S-Box
static void sub_bytes(unsigned char *state, size_t length)
{
    // Verifique se o estado possui 16 bytes
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

// Realiza a transformação de linhas (ShiftRows)
static void shift_rows(unsigned char *state)
{
    unsigned char temp;

    // Segunda linha: desloca 1 posição à esquerda
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Terceira linha: desloca 2 posições à esquerda
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Quarta linha: desloca 3 posições à esquerda
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

// Multiply in Galois Field (2^8)
static unsigned char gmul(unsigned char a, unsigned char b)
{
    unsigned char p = 0;
    for (int i = 0; i < 8; i++)
    {
        if (b & 1)
            p ^= a;

        int hi_bit_set = (a & 0x80); // Usando inteiro para representar booleano
        a <<= 1;
        if (hi_bit_set)
            a ^= 0x1B; // x^8 + x^4 + x^3 + x + 1 (AES irreducible polynomial)

        b >>= 1;
    }
    return p;
}

// Correct MixColumns implementation
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

    // Validação de entrada
    if (!input || !padded_length)
    {
        fprintf(stderr, "Entrada inválida para adicionar padding\n");
        exit(1);
    }

    // Verifica estouro de tamanho
    if (input_length > SIZE_MAX - block_size)
    {
        fprintf(stderr, "Tamanho de entrada muito grande para adicionar padding\n");
        exit(1);
    }

    // Calcula o tamanho do padding
    size_t padding = block_size - (input_length % block_size);
    if (padding == 0)
        padding = block_size; // Se já for múltiplo, adiciona um bloco cheio

    *padded_length = input_length + padding;

    // Aloca memória para os dados preenchidos
    unsigned char *padded_data = malloc(*padded_length);
    if (!padded_data)
    {
        perror("Erro ao alocar memória para padding");
        exit(1);
    }

    // Copia os dados de entrada para o buffer de saída
    memcpy(padded_data, input, input_length);

    // Preenche o restante do buffer com o valor do padding (PKCS7)
    memset(padded_data + input_length, padding, padding);

    return padded_data;
}

unsigned char *remove_padding(unsigned char *input, size_t input_length, size_t *output_length)
{
    if (input_length == 0)
    {
        fprintf(stderr, "Erro: input_length é zero.\n");
        exit(1);
    }

    unsigned char padding = input[input_length - 1];

    // Verificar se o padding é válido de acordo com o padrão PKCS7
    if (padding > AES_BLOCK_SIZE || padding == 0)
    {
        fprintf(stderr, "Erro: padding inválido (%d). input_length: %zu\n", padding, input_length);
        exit(1);
    }

    // Verificar se todos os bytes de padding são consistentes
    for (size_t i = input_length - padding; i < input_length; i++)
    {
        if (input[i] != padding)
        {
            fprintf(stderr, "Erro: bytes de padding inconsistentes\n");
            exit(1);
        }
    }

    *output_length = input_length - padding;

    unsigned char *output_data = malloc(*output_length);
    if (!output_data)
    {
        perror("Erro ao alocar memória para remover padding");
        exit(1);
    }

    memcpy(output_data, input, *output_length);

    return output_data;
}

// Criptografa um bloco
void aes_encrypt(const unsigned char *plaintext, unsigned char *ciphertext, const unsigned char *round_keys, int key_size)
{
    unsigned char state[AES_BLOCK_SIZE];
    memcpy(state, plaintext, AES_BLOCK_SIZE);

    int nr = key_size / 32 + 6; // Número de rodadas
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

//-------------------------------------------------------------------------------------------------------------------------------

// Função para substituir um byte usando a S-Box inversa
static unsigned char inv_sub_byte(unsigned char byte)
{
    return inv_s_box[byte];
}

// Função para substituir bytes usando a S-Box inversa
void inv_sub_bytes(unsigned char *state, size_t length)
{
    // Verifique se o estado possui 16 bytes
    if (length != 16)
    {
        fprintf(stderr, "Erro: o estado deve conter exatamente 16 bytes.\n");
        return;
    }

    // Realiza a substituição inversa
    for (size_t i = 0; i < 16; i++)
    {
        state[i] = inv_sub_byte(state[i]); // inv_sub_byte é a função de substituição
    }
}

// Função para inverter as linhas (InvShiftRows)
void inv_shift_rows(unsigned char *state)
{
    unsigned char temp;

    // Segunda Linha: rotaciona 1 byte para a direita
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    // Terceira Linha: rotaciona 2 bytes para a direita
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Quarta Linha: rotaciona 3 bytes para a direita
    temp = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = state[3];
    state[3] = temp;
}

// InvMixColumns implementation
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

// Função para descriptografar um bloco
void aes_decrypt(unsigned char *ciphertext, unsigned char *plaintext, const unsigned char *round_keys, int key_size)
{
    unsigned char state[AES_BLOCK_SIZE];
    memcpy(state, ciphertext, AES_BLOCK_SIZE);

    int nr = key_size / 32 + 6; // Número de rodadas

    // Primeira rodada: inverso da última rodada de criptografia
    add_round_key(state, round_keys);
    inv_shift_rows(state);
    inv_sub_bytes(state, sizeof(state));

    // Rodadas intermediárias
    for (int round = nr - 1; round > 0; round--)
    {
        add_round_key(state, round_keys + round * AES_BLOCK_SIZE);
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bytes(state, sizeof(state));
    }

    // Última rodada
    add_round_key(state, round_keys);

    memcpy(plaintext, state, AES_BLOCK_SIZE);
}