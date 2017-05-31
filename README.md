## AES Antiforgery

An alternative implementation of CSRF protection for ASP.Net MVC 6 which avoids the need to configure the Data Protection API (requires Redis or a UNC share), instead being able to pass in symmetric keys for the AES algorithm.

### Usage

#### Use the default environment variables

```bash
export AES_CSRF_KEY=PoQ2zO0w8A/n8eXl3eoN2AQXYhSIyMXJW2QVTzJOVA4=
export AES_CSRF_IV=L3RrIxqIug+XVp9/fiV4AQ==
```

```C#
var logger = p.GetService<ILogger<AesAntiforgery>>();
var timeout = TimeSpan.FromHours(12);

services.AddScoped<IAntiforgery, AesAntiforgery>(p => 
        new AesAntiforgery(logger, timeout));
```

#### Or get the configuration yourself

```C#
var logger = p.GetService<ILogger<AesAntiforgery>>();
var key = Convert.FromBase64String("PoQ2zO0w8A/n8eXl3eoN2AQXYhSIyMXJW2QVTzJOVA4=");
var iv = Convert.FromBase64String("L3RrIxqIug+XVp9/fiV4AQ==");
var timeout = TimeSpan.FromHours(12);

services.AddScoped<IAntiforgery, AesAntiforgery>(p => 
        new AesAntiforgery(logger, key, iv, timeout));
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