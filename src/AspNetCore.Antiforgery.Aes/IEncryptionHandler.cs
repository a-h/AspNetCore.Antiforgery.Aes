namespace AspNetCore.Antiforgery.Aes
{
    public interface IEncryptionHandler
    {
        string Encrypt(string plaintext);
        string Decrypt(string ciphertext);
    }
}