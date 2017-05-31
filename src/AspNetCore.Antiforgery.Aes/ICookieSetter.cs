using Microsoft.AspNetCore.Http;

namespace AspNetCore.Antiforgery.Aes
{
    public interface ICookieSetter
    {
        void Set(IResponseCookies cookies, string name, string value);
    }
}