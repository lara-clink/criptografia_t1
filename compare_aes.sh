#!/bin/bash

# Pastas e arquivos
INPUT_DIR="inputs"
OUTPUT_DIR="outputs"
INPUT_FILE="$INPUT_DIR/$1"
CUSTOM_ENCRYPT_FILE="$OUTPUT_DIR/custom_output.bin"
OPENSSL_ENCRYPT_FILE="$OUTPUT_DIR/openssl_encrypt.bin"
CUSTOM_DECRYPT_FILE="$OUTPUT_DIR/descrypt.txt"
OPENSSL_DECRYPT_FILE="$OUTPUT_DIR/openssl_decrypt.txt"

# Certifique-se de que as pastas outputs existam
mkdir -p $OUTPUT_DIR

# Verificar se o arquivo de entrada existe
if [ ! -f "$INPUT_FILE" ]; then
    echo "Erro: Arquivo de entrada '$INPUT_FILE' não encontrado."
    exit 1
fi

# Criptografia customizada
echo "Executando o programa customizado..."
CUSTOM_ENCRYPT_TIME=$( { time ./aes "$INPUT_FILE" "custom_output.bin" encrypt; } 2>&1 | grep real | awk '{print $2}' )

# Criptografia com OpenSSL
echo "Executando o OpenSSL para criptografia..."
OPENSSL_ENCRYPT_TIME=$( { time openssl enc -aes-128-cbc -in "$INPUT_FILE" -out "$OPENSSL_ENCRYPT_FILE" -k secret; } 2>&1 | grep real | awk '{print $2}' )

# Descriptografia customizada
echo "Executando o programa customizado para descriptografia..."
CUSTOM_DECRYPT_TIME=$( { time ./aes "$CUSTOM_ENCRYPT_FILE" "descrypt.txt" decrypt; } 2>&1 | grep real | awk '{print $2}' )

# Descriptografia com OpenSSL
echo "Executando o OpenSSL para descriptografia..."
OPENSSL_DECRYPT_TIME=$( { time openssl enc -d -aes-128-cbc -in "$OPENSSL_ENCRYPT_FILE" -out "$OPENSSL_DECRYPT_FILE" -k secret; } 2>&1 | grep real | awk '{print $2}' )

# Exibir tempos
echo "Tempo de criptografia customizada: $CUSTOM_ENCRYPT_TIME segundos"
echo "Tempo de criptografia OpenSSL: $OPENSSL_ENCRYPT_TIME segundos"
echo "Tempo de descriptografia customizada: $CUSTOM_DECRYPT_TIME segundos"
echo "Tempo de descriptografia OpenSSL: $OPENSSL_DECRYPT_TIME segundos"
