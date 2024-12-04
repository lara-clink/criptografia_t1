#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "aes.h"

// Função para medir o tempo em segundos
double measure_time(clock_t start, clock_t end)
{
    return ((double)(end - start)) / CLOCKS_PER_SEC;
}

// Função para ler arquivo
unsigned char *read_file(const char *filename, size_t *length)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        perror("Erro ao abrir arquivo");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *length = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *buffer = malloc(*length);
    if (!buffer)
    {
        perror("Erro ao alocar memória");
        fclose(file);
        return NULL;
    }

    fread(buffer, 1, *length, file);
    fclose(file);

    return buffer;
}

// Função para escrever arquivo
void write_file(const char *filename, unsigned char *data, size_t length)
{
    FILE *file = fopen(filename, "wb");
    if (!file)
    {
        perror("Erro ao escrever arquivo");
        return;
    }

    fwrite(data, 1, length, file);
    fclose(file);
}

int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        printf("Uso: %s <input_file> <output_file> <mode: encrypt|decrypt>\n", argv[0]);
        return 1;
    }

    const char *input_file = argv[1];
    const char *output_file = argv[2];
    const char *mode = argv[3];

    size_t input_length;
    unsigned char *input_data = read_file(input_file, &input_length);
    if (!input_data)
    {
        return 1;
    }

    if (input_length % AES_BLOCK_SIZE != 0)
    {
        printf("Erro: O tamanho do arquivo deve ser múltiplo de %d bytes\n", AES_BLOCK_SIZE);
        free(input_data);
        return 1;
    }

    // Gerar chave de 128 bits
    unsigned char key[16];
    for (int i = 0; i < 16; i++)
    {
        key[i] = rand() % 256;
    }

    // Expandir chaves de rodada
    unsigned char round_keys[176]; // Para AES-128: 44 words (176 bytes)
    aes_key_expansion(key, round_keys, 128);

    // Alocar memória para saída
    unsigned char *output_data = malloc(input_length);
    if (!output_data)
    {
        perror("Erro ao alocar memória para saída");
        free(input_data);
        return 1;
    }

    clock_t start, end;

    // Criptografar ou descriptografar
    start = clock();
    if (strcmp(mode, "encrypt") == 0)
    {
        for (size_t i = 0; i < input_length; i += AES_BLOCK_SIZE)
        {
            aes_encrypt(input_data + i, output_data + i, round_keys, 128);
        }
    }
    else if (strcmp(mode, "decrypt") == 0)
    {
        for (size_t i = 0; i < input_length; i += AES_BLOCK_SIZE)
        {
            aes_decrypt(input_data + i, output_data + i, round_keys, 128);
        }
    }
    else
    {
        printf("Modo inválido: use 'encrypt' ou 'decrypt'\n");
        free(input_data);
        free(output_data);
        return 1;
    }
    end = clock();

    // Escrever saída no arquivo
    write_file(output_file, output_data, input_length);

    // Medir tempo de execução
    printf("Tempo total (%s): %.6f segundos\n", mode, measure_time(start, end));

    // Liberar memória
    free(input_data);
    free(output_data);

    return 0;
}
