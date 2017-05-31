## AES Antiforgery

An alternative implementation of CSRF protection for ASP.Net MVC 6 which avoids the need to configure the Data Protection API (requires Redis or a UNC share), instead being able to pass in symmetric keys for the AES algorithm.

### Usage

```C#
services.AddScoped<IAntiforgery, AesAntiforgery>(p => new AesAntiforgery(p.GetService<ILogger<AesAntiforgery>>(), config.Key, config.IV, TimeSpan.FromHours(12)));
```

### Key generation

```C#
public static void Main()
{
    using (var aes = System.Security.Cryptography.Aes.Create())
    {
        Console.WriteLine("Key: " + Convert.ToBase64String(aes.Key));
        Console.WriteLine("IV: " + Convert.ToBase64String(aes.IV));
    }
}
```