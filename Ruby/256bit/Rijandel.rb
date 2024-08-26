require 'openssl'
require 'securerandom'

def aes_encrypt(plaintext, key)
  cipher = OpenSSL::Cipher.new('aes-256-cbc')
  cipher.encrypt
  iv = cipher.random_iv
  cipher.key = key

  ciphertext = cipher.update(plaintext) + cipher.final
  iv + ciphertext
end

def main
  key = SecureRandom.random_bytes(32) # 256-bit key
  plaintext = "This is a test message for AES-256 encryption!"

  ciphertext = aes_encrypt(plaintext, key)

  puts "Ciphertext is: #{ciphertext.unpack1('H*')}"
end

main
