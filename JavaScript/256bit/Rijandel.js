const crypto = require('crypto');

function aesEncrypt(text, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + encrypted;
}

function main() {
    const key = crypto.randomBytes(32); // 256-bit key
    const plaintext = "This is a test message for AES-256 encryption!";
    
    const ciphertext = aesEncrypt(plaintext, key);
    
    console.log("Ciphertext is: " + ciphertext);
}

main();
