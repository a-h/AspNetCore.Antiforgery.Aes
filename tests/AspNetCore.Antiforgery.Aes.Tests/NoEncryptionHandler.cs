using System;

namespace AspNetCore.Antiforgery.Aes.Tests
{
    public class NoEncryptionHander : IEncryptionHandler
    {
        string IEncryptionHandler.Decrypt(string ciphertext)
        {
            return ciphertext;
        }

        string IEncryptionHandler.Encrypt(string plaintext)
        {
            return plaintext;
        }
    }
}