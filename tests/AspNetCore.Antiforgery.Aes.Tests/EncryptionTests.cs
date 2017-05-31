using System;
using Xunit;

namespace AspNetCore.Antiforgery.Aes.Tests
{
    public class EncryptionTests
    {
        [Fact]
        public void ItIsPossibleToEncryptAndDecryptData()
        {
            var key = Convert.FromBase64String("PoQ2zO0w8A/n8eXl3eoN2AQXYhSIyMXJW2QVTzJOVA4=");
            var iv = Convert.FromBase64String("L3RrIxqIug+XVp9/fiV4AQ==");
            var encryption = new EncryptionHandler(key, iv);

            var plaintext = "Behaviour test";
            var ciphertext = encryption.Encrypt(plaintext);
            var decrypted = encryption.Decrypt(ciphertext);

            Assert.NotEqual(plaintext, ciphertext);
            Assert.Equal(plaintext, decrypted);
        }
    }
}