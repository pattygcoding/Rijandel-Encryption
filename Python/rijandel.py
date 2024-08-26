from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def encrypt_aes(key, plaintext):
    # Generate a random initialization vector (IV)
    iv = os.urandom(16)
    
    # Create a cipher object with the given key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    
    # Encrypt the plaintext
    encryptor = cipher.encryptor()
    
    # Pad the plaintext to be a multiple of the block size (16 bytes for AES)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return iv + ciphertext

def decrypt_aes(key, ciphertext):
    # Extract the IV from the beginning of the ciphertext
    iv = ciphertext[:16]
    
    # Extract the actual ciphertext
    ciphertext = ciphertext[16:]
    
    # Create a cipher object with the given key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    
    # Decrypt the ciphertext
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    
    return plaintext

# Example usage
key = os.urandom(32)  # AES-256 key
plaintext = b"This is a secret message"

ciphertext = encrypt_aes(key, plaintext)
print("Encrypted:", ciphertext)

decrypted_message = decrypt_aes(key, ciphertext)
print("Decrypted:", decrypted_message)
