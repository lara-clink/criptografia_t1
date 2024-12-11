# Projeto: Comparação de Criptografia AES

## Informações Gerais

Este projeto implementa uma solução personalizada para criptografia e descriptografia utilizando o algoritmo **AES (Advanced Encryption Standard)**. Além disso, inclui um script que compara o desempenho e a correção entre a implementação customizada e o **OpenSSL**, uma biblioteca padrão para operações criptográficas.

### Alunos:

- **Lara Ricalde Machado Clink**
- **Vinicius Oliveira dos Santos**

### Professor:

- **Luis Carlos Pessoa Albini**

---

## Estrutura do Projeto

### Diretórios

- **inputs/**: Contém os arquivos de entrada que serão utilizados para criptografia e descriptografia.

  - Exemplos: `lusiadas.txt`, `plaintext.txt`

- **outputs/**: Contém os arquivos gerados durante o processo:
  - `custom_output.bin`: Arquivo criptografado pela implementação customizada.
  - `encryption_key.bin`: Chave utilizada durante a criptografia.
  - `descrypt.txt`: Arquivo descriptografado pela implementação customizada.
  - `openssl_encrypt.bin`: Arquivo criptografado pelo OpenSSL.
  - `openssl_decrypt.txt`: Arquivo descriptografado pelo OpenSSL.

---

## Dependências

1. **Compilador C**:
   - GCC ou equivalente.
2. **OpenSSL**:
   - Necessário para realizar operações de criptografia e descriptografia com a biblioteca padrão.
3. **Shell Script**:
   - Para executar o script de comparação.

---

## Como Compilar

Use o seguinte comando para compilar o programa:

```bash
gcc -o aes main.c aes.c -I.
```
## Como Executar
### Criptografar

Para criptografar um arquivo de entrada, execute:

./aes inputs/arquivo.txt custom_output.bin encrypt

### Descriptografar

Para descriptografar um arquivo de saída gerado anteriormente:

./aes custom_output.bin outputs/descrypt.txt decrypt

## Comparação com OpenSSL

O script compare_aes.sh é usado para comparar a implementação customizada com o OpenSSL. Ele mede o tempo de execução de cada processo e verifica a correção das saídas geradas.
Executando o Script de Comparação

./compare_aes.sh inputs/lusiadas.txt

## Exemplo de Saída

Executando o programa customizado...
Total time (encrypt): 0.001234 seconds
Tempo de criptografia customizada: 0.0012 segundos

Executando o OpenSSL para criptografia...
Tempo de criptografia OpenSSL: 0.0015 segundos

Executando o programa customizado para descriptografia...
Total time (decrypt): 0.001456 seconds
Tempo de descriptografia customizada: 0.0014 segundos

Executando o OpenSSL para descriptografia...
Tempo de descriptografia OpenSSL: 0.0013 segundos

Comparando saídas...
Saída do programa customizado correta!
OpenSSL produziu a saída correta para descriptografia!

## Notas Importantes

    Padding:
        Este projeto utiliza o esquema PKCS#7 para garantir que o tamanho do arquivo de entrada seja múltiplo de 16 bytes.
    Segurança:
        A chave para criptografia/descriptografia é gerada utilizando /dev/urandom, uma fonte segura de números aleatórios.
    OpenSSL:
        Pode exibir avisos relacionados ao uso de métodos legados (deprecated key derivation). Esses avisos não afetam o funcionamento do programa.

## Estrutura do Script de Comparação (compare_aes.sh)

O script realiza os seguintes passos:

    Criptografa e descriptografa o arquivo utilizando a implementação customizada.
    Criptografa e descriptografa o mesmo arquivo utilizando o OpenSSL.
    Compara os tempos de execução.
    Verifica se os arquivos descriptografados são idênticos ao arquivo original.

## Licença

Este projeto foi desenvolvido para fins acadêmicos no curso ministrado pelo professor Luis Carlos Pessoa Albini. Qualquer uso externo deve ser autorizado pelos autores.
