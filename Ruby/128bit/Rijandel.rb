require 'openssl'
require 'securerandom'

def aes_encrypt(plaintext, key)
  cipher = OpenSSL::Cipher.new('aes-128-cbc')
  cipher.encrypt
  iv = cipher.random_iv
  cipher.key = key

  ciphertext = cipher.update(plaintext) + cipher.final
  iv + ciphertext
end

def main
  key = SecureRandom.random_bytes(16) # 128-bit key
  plaintext = "This is a test message for AES-128 encryption!"

  ciphertext = aes_encrypt(plaintext, key)

  puts "Ciphertext is: #{ciphertext.unpack1('H*')}"
end

main
