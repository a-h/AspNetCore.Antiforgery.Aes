using System;

namespace AspNetCore.Antiforgery.Aes
{
    public class StaticSettingProvider : ISettingProvider
    {
        public StaticSettingProvider(byte[] key, byte[] iv)
        {
            this.Key = key;
            this.IV = iv;
        }

        public byte[] Key { get; private set; }
        public byte[] IV { get; private set; }
    }
}