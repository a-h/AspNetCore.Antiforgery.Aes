using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AspNetCore.Antiforgery.Aes
{
    public class EncryptionHandler : IEncryptionHandler
    {
        private byte[] _key;
        private byte[] _iv;

        public EncryptionHandler(byte[] key, byte[] iv)
        {
            this._key = key;
            this._iv = iv;
        }

        public string Encrypt(string s)
        {
            using (var aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Key = _key;
                aes.IV = _iv;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    using (var resultStream = new MemoryStream())
                    {
                        using (var aesStream = new CryptoStream(resultStream, encryptor, CryptoStreamMode.Write))
                        {
                            using (var plainStream = new MemoryStream(Encoding.UTF8.GetBytes(s)))
                            {
                                plainStream.CopyTo(aesStream);
                            }
                        }

                        return Convert.ToBase64String(resultStream.ToArray());
                    }
                }
            }
        }

        public string Decrypt(string s)
        {
            var op = new MemoryStream();

            using (var aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Key = _key;
                aes.IV = _iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    using (var inputStream = new MemoryStream(Convert.FromBase64String(s)))
                    {
                        using (var decryptedStream = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read))
                        {
                            decryptedStream.CopyTo(op);
                        }
                    }
                }
            }

            return Encoding.UTF8.GetString(op.ToArray());
        }
    }
}