#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <vector>
#include <cstring>

std::vector<unsigned char> encrypt_aes(const std::vector<unsigned char>& key, const std::vector<unsigned char>& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    std::vector<unsigned char> iv(EVP_MAX_IV_LENGTH);

    // Generate random IV
    if (!RAND_bytes(iv.data(), iv.size())) {
        throw std::runtime_error("Failed to generate IV");
    }

    // Initialize encryption operation
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data())) {
        throw std::runtime_error("Encryption init failed");
    }

    int len;
    int ciphertext_len;

    // Encrypt the data
    if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) {
        throw std::runtime_error("Encryption failed");
    }
    ciphertext_len = len;

    // Finalize encryption
    if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        throw std::runtime_error("Final encryption step failed");
    }
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);
    ciphertext.insert(ciphertext.begin(), iv.begin(), iv.end()); // Prepend IV to ciphertext

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::vector<unsigned char> decrypt_aes(const std::vector<unsigned char>& key, const std::vector<unsigned char>& ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> plaintext(ciphertext.size());
    std::vector<unsigned char> iv(ciphertext.begin(), ciphertext.begin() + EVP_MAX_IV_LENGTH);

    // Initialize decryption operation
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data())) {
        throw std::runtime_error("Decryption init failed");
    }

    int len;
    int plaintext_len;

    // Decrypt the data
    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data() + EVP_MAX_IV_LENGTH, ciphertext.size() - EVP_MAX_IV_LENGTH)) {
        throw std::runtime_error("Decryption failed");
    }
    plaintext_len = len;

    // Finalize decryption
    if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        throw std::runtime_error("Final decryption step failed");
    }
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

int main() {
    // Example key and plaintext
    std::vector<unsigned char> key(32); // 256-bit key
    if (!RAND_bytes(key.data(), key.size())) {
        std::cerr << "Failed to generate random key" << std::endl;
        return 1;
    }

    std::string message = "This is a secret message";
    std::vector<unsigned char> plaintext(message.begin(), message.end());

    // Encrypt the plaintext
    std::vector<unsigned char> ciphertext = encrypt_aes(key, plaintext);

    std::cout << "Encrypted message (in hex): ";
    for (unsigned char c : ciphertext) {
        printf("%02x", c);
    }
    std::cout << std::endl;

    // Decrypt the ciphertext
    std::vector<unsigned char> decrypted_message = decrypt_aes(key, ciphertext);
    std::string decrypted_text(decrypted_message.begin(), decrypted_message.end());

    std::cout << "Decrypted message: " << decrypted_text << std::endl;

    return 0;
}
