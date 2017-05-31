using System;

namespace AspNetCore.Antiforgery.Aes
{
    public class EnvironmentSettingProvider : ISettingProvider
    {
        public EnvironmentSettingProvider()
        {
            this.Key = ParseFromEnvironment("AES_CSRF_KEY");
            this.IV = ParseFromEnvironment("AES_CSRF_IV");
        }

        private byte[] ParseFromEnvironment(string name)
        {
            var value = Environment.GetEnvironmentVariable(name);
            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentException($"The {name} environment variable is missing.", name);
            }

            try
            {
                return Convert.FromBase64String(value);
            }
            catch (Exception ex)
            {
                throw new ArgumentException($"Failed to parse base64 data from environment variable {name}", name, ex);
            }
        }

        public byte[] Key { get; private set; }
        public byte[] IV { get; private set; }
    }
}