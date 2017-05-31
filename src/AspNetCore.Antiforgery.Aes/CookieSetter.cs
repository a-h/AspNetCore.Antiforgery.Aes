using Microsoft.AspNetCore.Http;

namespace AspNetCore.Antiforgery.Aes
{
    public class CookieSetter : ICookieSetter
    {
        public void Set(IResponseCookies cookies, string name, string value)
        {
            cookies.Append(name, value);
        }
    }
}