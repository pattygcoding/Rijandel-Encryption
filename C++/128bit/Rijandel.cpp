#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <vector>
#include <cstring>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void aes_encrypt(const unsigned char* plaintext, int plaintext_len, const unsigned char* key,
                 const unsigned char* iv, unsigned char* ciphertext, int& ciphertext_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    int len;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    // 128-bit key
    unsigned char key[16];
    if (!RAND_bytes(key, sizeof(key))) handleErrors();

    // 128-bit IV
    unsigned char iv[16];
    if (!RAND_bytes(iv, sizeof(iv))) handleErrors();

    const char* plaintext = "This is a test message for AES-128 encryption!";
    unsigned char ciphertext[128];
    int ciphertext_len;

    aes_encrypt((unsigned char*)plaintext, strlen(plaintext), key, iv, ciphertext, ciphertext_len);

    std::cout << "Ciphertext is: ";
    for (int i = 0; i < ciphertext_len; i++)
        std::cout << std::hex << (int)ciphertext[i];
    std::cout << std::endl;

    return 0;
}
