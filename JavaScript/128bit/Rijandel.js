const crypto = require('crypto');

function aesEncrypt(text, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + encrypted;
}

function main() {
    const key = crypto.randomBytes(16); // 128-bit key
    const plaintext = "This is a test message for AES-128 encryption!";
    
    const ciphertext = aesEncrypt(plaintext, key);
    
    console.log("Ciphertext is: " + ciphertext);
}

main();
