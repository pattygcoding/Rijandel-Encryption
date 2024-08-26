from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(plaintext)
    return cipher.iv + ciphertext

def pad(data):
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len] * pad_len)

def main():
    key = get_random_bytes(24)  # 192-bit key
    plaintext = b"This is a test message for AES-192 encryption!"
    plaintext = pad(plaintext)

    ciphertext = aes_encrypt(plaintext, key)

    print("Ciphertext is:", ciphertext.hex())

if __name__ == "__main__":
    main()
