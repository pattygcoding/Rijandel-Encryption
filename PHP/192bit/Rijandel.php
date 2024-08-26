<?php
function aesEncrypt($plaintext, $key) {
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-192-cbc'));
    $ciphertext = openssl_encrypt($plaintext, 'aes-192-cbc', $key, OPENSSL_RAW_DATA, $iv);
    return bin2hex($iv . $ciphertext);
}

function main() {
    $key = openssl_random_pseudo_bytes(24); // 192-bit key
    $plaintext = "This is a test message for AES-192 encryption!";
    
    $ciphertext = aesEncrypt($plaintext, $key);
    
    echo "Ciphertext is: " . $ciphertext . PHP_EOL;
}

main();
?>
