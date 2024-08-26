#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int main(void) {
    unsigned char key[32]; // 256-bit key
    if(!RAND_bytes(key, sizeof(key))) handleErrors();

    unsigned char iv[16]; // 128-bit IV
    if(!RAND_bytes(iv, sizeof(iv))) handleErrors();

    unsigned char *plaintext = (unsigned char *)"This is a test message for AES-256 encryption!";
    unsigned char ciphertext[128];

    int ciphertext_len = aes_encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext);

    printf("Ciphertext is: ");
    for(int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    return 0;
}
