namespace AspNetCore.Antiforgery.Aes
{
    public interface ISettingProvider
    {
        byte[] Key { get; }
        byte[] IV { get; }
    }
}