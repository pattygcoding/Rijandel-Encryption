import * as crypto from 'crypto';

function aesEncrypt(plaintext: string, key: Buffer): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-192-cbc', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + encrypted;
}

function main() {
    const key = crypto.randomBytes(24); // 192-bit key
    const plaintext = "This is a test message for AES-192 encryption!";
    
    const ciphertext = aesEncrypt(plaintext, key);
    
    console.log("Ciphertext is: " + ciphertext);
}

main();
