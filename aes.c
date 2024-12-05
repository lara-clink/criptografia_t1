#include <stdio.h>
#include <string.h>
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
static void sub_bytes(unsigned char *state)
{
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

// Mistura as colunas (MixColumns) - versão simplificada
static void mix_columns(unsigned char *state)
{
    for (int i = 0; i < 4; i++)
    {
        unsigned char *col = state + i * 4;
        unsigned char a = col[0], b = col[1], c = col[2], d = col[3];

        col[0] = a ^ b ^ c ^ d; // Implementação simplificada
        col[1] = b ^ c ^ d ^ a;
        col[2] = c ^ d ^ a ^ b;
        col[3] = d ^ a ^ b ^ c;
    }
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
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys + round * AES_BLOCK_SIZE);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys + nr * AES_BLOCK_SIZE);

    memcpy(ciphertext, state, AES_BLOCK_SIZE);
}

//-------------------------------------------------------------------------------------------------------------------------------

// Função para gerar a tabela inversa (Inverse S-Box)
void generate_inv_s_box(const unsigned char *s_box, unsigned char *inv_s_box)
{
    for (int i = 0; i < 256; i++)
    {
        inv_s_box[s_box[i]] = i;
    }
}

// Função para substituir bytes usando a S-Box inversa
static void inv_sub_bytes(unsigned char *state, const unsigned char *inv_s_box)
{
    for (int i = 0; i < 16; i++)
    {
        state[i] = inv_s_box[state[i]];
    }
}

// Função para inverter as linhas (InvShiftRows)
void inv_shift_rows(unsigned char *state)
{
    unsigned char temp;

    // Linha 1: rotaciona 1 byte para a direita
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    // Linha 2: rotaciona 2 bytes para a direita
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Linha 3: rotaciona 3 bytes para a direita
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

// Função para multiplicar no campo finito GF(2^8)
static unsigned char gf_mul(unsigned char a, unsigned char b)
{
    unsigned char p = 0;
    unsigned char hi_bit_set;
    for (int i = 0; i < 8; i++)
    {
        if (b & 1)
        {
            p ^= a;
        }
        hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set)
        {
            a ^= 0x1b; // Polinômio irreducível
        }
        b >>= 1;
    }
    return p;
}

// Mistura inversa das colunas (InvMixColumns)
static void inv_mix_columns(unsigned char *state)
{
    for (int i = 0; i < 4; i++)
    {
        unsigned char *col = state + i * 4;
        unsigned char a = col[0], b = col[1], c = col[2], d = col[3];

        col[0] = gf_mul(a, 0x0e) ^ gf_mul(b, 0x0b) ^ gf_mul(c, 0x0d) ^ gf_mul(d, 0x09);
        col[1] = gf_mul(a, 0x09) ^ gf_mul(b, 0x0e) ^ gf_mul(c, 0x0b) ^ gf_mul(d, 0x0d);
        col[2] = gf_mul(a, 0x0d) ^ gf_mul(b, 0x09) ^ gf_mul(c, 0x0e) ^ gf_mul(d, 0x0b);
        col[3] = gf_mul(a, 0x0b) ^ gf_mul(b, 0x0d) ^ gf_mul(c, 0x09) ^ gf_mul(d, 0x0e);
    }
}

// Função para expandir a chave
void inv_aes_key_expansion(const unsigned char *key, unsigned char *round_keys, int key_size)
{
    int i, j;
    unsigned char temp[4], k;
    int Nk = key_size / 32; // Número de palavras na chave
    int Nr = Nk + 6;        // Número de rodadas

    // Copia a chave inicial para as primeiras palavras da chave expandida
    for (i = 0; i < Nk; i++)
    {
        round_keys[i * 4] = key[i * 4];
        round_keys[i * 4 + 1] = key[i * 4 + 1];
        round_keys[i * 4 + 2] = key[i * 4 + 2];
        round_keys[i * 4 + 3] = key[i * 4 + 3];
    }

    // Gera as palavras restantes da chave expandida
    for (i = Nk; i < 4 * (Nr + 1); i++)
    {
        temp[0] = round_keys[(i - 1) * 4];
        temp[1] = round_keys[(i - 1) * 4 + 1];
        temp[2] = round_keys[(i - 1) * 4 + 2];
        temp[3] = round_keys[(i - 1) * 4 + 3];

        if (i % Nk == 0)
        {
            // RotWord
            k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;

            // SubWord
            temp[0] = s_box[temp[0]];
            temp[1] = s_box[temp[1]];
            temp[2] = s_box[temp[2]];
            temp[3] = s_box[temp[3]];

            // Rcon
            temp[0] ^= (0x01 << ((i / Nk) - 1));
        }
        else if (Nk > 6 && i % Nk == 4)
        {
            // SubWord
            temp[0] = s_box[temp[0]];
            temp[1] = s_box[temp[1]];
            temp[2] = s_box[temp[2]];
            temp[3] = s_box[temp[3]];
        }

        round_keys[i * 4] = round_keys[(i - Nk) * 4] ^ temp[0];
        round_keys[i * 4 + 1] = round_keys[(i - Nk) * 4 + 1] ^ temp[1];
        round_keys[i * 4 + 2] = round_keys[(i - Nk) * 4 + 2] ^ temp[2];
        round_keys[i * 4 + 3] = round_keys[(i - Nk) * 4 + 3] ^ temp[3];
    }
}

// Função principal de descriptografia AES
void aes_decrypt(unsigned char *input, unsigned char *output, const unsigned char *key, int key_size)
{
    unsigned char state[AES_BLOCK_SIZE];
    unsigned char inv_s_box[256];
    unsigned char round_keys[176]; // 11 * 16 bytes para 128-bit AES

    generate_inv_s_box(s_box, inv_s_box);

    // Copia o input para o estado
    memcpy(state, input, AES_BLOCK_SIZE);

    // Gera as chaves de rodada
    aes_key_expansion(key, round_keys, key_size);

    // Adiciona a última chave de rodada
    add_round_key(state, round_keys + 160);

    int nr = key_size / 32 + 6; // Número de rodadas

    // Realiza as rodadas de descriptografia
    for (int round = nr - 1; round >= 1; round--)
    {
        inv_shift_rows(state);
        inv_sub_bytes(state, inv_s_box);
        add_round_key(state, round_keys + round * 16);
        inv_mix_columns(state);
    }

    // Última rodada (sem inv_mix_columns)
    inv_shift_rows(state);
    inv_sub_bytes(state, inv_s_box);
    add_round_key(state, round_keys);

    // Copia o estado para o output
    memcpy(output, state, AES_BLOCK_SIZE);
}