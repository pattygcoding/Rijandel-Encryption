using System;
using System.Security.Cryptography;
using System.Text;

class Aes128Encryption
{
    static void Main()
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.KeySize = 128;
            aesAlg.GenerateKey();
            aesAlg.GenerateIV();

            byte[] encrypted = EncryptStringToBytes_Aes("This is a test message for AES-128 encryption!", aesAlg.Key, aesAlg.IV);

            Console.WriteLine("Ciphertext is: " + BitConverter.ToString(encrypted).Replace("-", ""));
        }
    }

    static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
    {
        if (plainText == null || plainText.Length <= 0)
            throw new ArgumentNullException(nameof(plainText));
        if (Key == null || Key.Length <= 0)
            throw new ArgumentNullException(nameof(Key));
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException(nameof(IV));

        byte[] encrypted;

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (System.IO.MemoryStream msEncrypt = new System.IO.MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                using (System.IO.StreamWriter swEncrypt = new System.IO.StreamWriter(csEncrypt))
                {
                    swEncrypt.Write(plainText);
                }
                encrypted = msEncrypt.ToArray();
            }
        }

        return encrypted;
    }
}
