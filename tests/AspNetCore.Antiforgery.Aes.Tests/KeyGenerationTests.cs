using System;
using Xunit;

namespace AspNetCore.Antiforgery.Aes.Tests
{
    public class KeyGenerationTests
    {
        [Fact]
        public void ItIsPossibleToGenerateNewKeys()
        {
            using (var aes = System.Security.Cryptography.Aes.Create())
            {
                Console.WriteLine("export AES_CSRF_KEY=" + Convert.ToBase64String(aes.Key));
                Console.WriteLine("export AES_CSRF_IV=" + Convert.ToBase64String(aes.IV));
            }
        }
    }
}