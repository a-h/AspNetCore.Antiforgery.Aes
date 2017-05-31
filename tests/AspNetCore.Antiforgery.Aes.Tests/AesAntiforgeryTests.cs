using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using NSubstitute;
using Xunit;

namespace AspNetCore.Antiforgery.Aes.Tests
{
    public class AesAntiforgeryTests
    {
        [Fact]
        public void GetAndStoreTokensSetsNoCacheHeaders()
        {
            // Arrange
            var ctx = new DefaultHttpContext();
            var mlogger = Substitute.For<ILogger<AesAntiforgery>>();
            var encryption = new NoEncryptionHander();
            var cookieSetter = Substitute.For<ICookieSetter>();

            var af = new AesAntiforgery(mlogger, TimeSpan.FromHours(12), encryption, cookieSetter);

            // Act
            af.GetAndStoreTokens(ctx);

            // Assert
            Assert.True(ctx.Response.Headers.ContainsKey("Cache-control")
                && ctx.Response.Headers["Cache-control"] == "no-cache", "Expected Cache-control header to be set.");
            Assert.True(ctx.Response.Headers.ContainsKey("Pragma")
                && ctx.Response.Headers["Pragma"] == "no-cache", "Expected Pragma header to be set.");
            Assert.True(ctx.Response.Headers.ContainsKey("X-Frame-Options")
                && ctx.Response.Headers["X-Frame-Options"] == "SAMEORIGIN", "Expected X-Frame-Options header to be set.");
        }

        [Fact]
        public void GetAndStoreTokensSetsTheCookie()
        {
            // Arrange
            var ctx = new DefaultHttpContext();
            var mlogger = Substitute.For<ILogger<AesAntiforgery>>();
            var encryption = new NoEncryptionHander();
            var cookieSetter = Substitute.For<ICookieSetter>();

            var af = new AesAntiforgery(mlogger, TimeSpan.FromHours(12), encryption, cookieSetter);

            // Act
            af.GetAndStoreTokens(ctx);

            // Assert
            cookieSetter.Received().Set(Arg.Any<IResponseCookies>(), "csrf_requestid_cookie", Arg.Any<string>());
        }

        [Fact]
        public void CallingGetTokensTwiceReturnsTheSameSetOfTokens()
        {
            // Arrange
            var ctx = new DefaultHttpContext();
            var mlogger = Substitute.For<ILogger<AesAntiforgery>>();
            var encryption = new NoEncryptionHander();
            var cookieSetter = Substitute.For<ICookieSetter>();

            var af = new AesAntiforgery(mlogger, TimeSpan.FromHours(12), encryption, cookieSetter);

            // Act
            var set1 = af.GetTokens(ctx);
            var set2 = af.GetTokens(ctx);

            // Assert
            Assert.Equal(set1.CookieToken, set2.CookieToken);
            Assert.Equal(set1.FormFieldName, set2.FormFieldName);
            Assert.Equal(set1.HeaderName, set2.HeaderName);
            Assert.Equal(set1.RequestToken, set2.RequestToken);
        }

        [Fact]
        public async Task IsRequestValidAsyncSkipsGetRequests()
        {
            await IsRequestValidAsyncSkipsVerb("GET");
        }

        public async Task IsRequestValidAsyncSkipsOptionsRequests()
        {
            await IsRequestValidAsyncSkipsVerb("OPTIONS");
        }

        public async Task IsRequestValidAsyncSkipsHeadRequests()
        {
            await IsRequestValidAsyncSkipsVerb("HEAD");
        }

        public async Task IsRequestValidAsyncSkipsTraceRequests()
        {
            await IsRequestValidAsyncSkipsVerb("TRACE");
        }

        public async Task IsRequestValidAsyncSkipsVerb(string verb)
        {
            // Arrange
            var ctx = new DefaultHttpContext();
            var encryption = new NoEncryptionHander();
            var cookieSetter = Substitute.For<ICookieSetter>();
            var mlogger = Substitute.For<ILogger<AesAntiforgery>>();

            var af = new AesAntiforgery(mlogger, TimeSpan.FromHours(12), encryption, cookieSetter);

            // Act
            ctx.Request.Method = verb;
            var isValid = await af.IsRequestValidAsync(ctx);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public async Task IsRequestValidAsyncAllowsRequestsWithAValidCookieAndFormPost()
        {
            // Arrange
            var ctx = new DefaultHttpContext();
            var encryption = new NoEncryptionHander();
            var cookieSetter = Substitute.For<ICookieSetter>();
            var mlogger = Substitute.For<ILogger<AesAntiforgery>>();

            var af = new AesAntiforgery(mlogger, TimeSpan.FromHours(12), encryption, cookieSetter);

            var valuesToValidate = af.CreateAntiforgeryTokenSet();

            ctx.Request.Method = "POST";
            // Add the valid form token.
            ctx.Request.Form = new FormCollection(new Dictionary<string, StringValues>
            {
                { valuesToValidate.FormFieldName, valuesToValidate.RequestToken },
            });
            // Add the valid cookie.
            var cookies = new RequestCookieCollection(new Dictionary<string, string>
            {
                { "csrf_requestid_cookie", valuesToValidate.CookieToken },
            });
            ctx.Request.Cookies = cookies;

            // Act
            var isValid = await af.IsRequestValidAsync(ctx);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public async Task IsRequestValidAsyncAllowsRequestsWithAValidCookieAndHTTPHeader()
        {
            // Arrange
            var ctx = new DefaultHttpContext();
            var encryption = new NoEncryptionHander();
            var cookieSetter = Substitute.For<ICookieSetter>();
            var mlogger = Substitute.For<ILogger<AesAntiforgery>>();

            var af = new AesAntiforgery(mlogger, TimeSpan.FromHours(12), encryption, cookieSetter);

            var valuesToValidate = af.CreateAntiforgeryTokenSet();

            ctx.Request.Method = "POST";
            ctx.Request.ContentType = "application/json";
            // Add the valid header token.
            ctx.Request.Headers.Add(valuesToValidate.HeaderName, valuesToValidate.RequestToken);
            // Add the valid cookie.
            var cookies = new RequestCookieCollection(new Dictionary<string, string>
            {
                { "csrf_requestid_cookie", valuesToValidate.CookieToken },
            });
            ctx.Request.Cookies = cookies;

            // Act
            var isValid = await af.IsRequestValidAsync(ctx);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public async Task IsRequestValidAsyncAllowsRequestsWithAValidCookieAndHTTPHeaderWithEncryption()
        {
            // Arrange
            var ctx = new DefaultHttpContext();

            var key = Convert.FromBase64String("PoQ2zO0w8A/n8eXl3eoN2AQXYhSIyMXJW2QVTzJOVA4=");
            var iv = Convert.FromBase64String("L3RrIxqIug+XVp9/fiV4AQ==");

            var encryption = new EncryptionHandler(key, iv);
            var cookieSetter = Substitute.For<ICookieSetter>();
            var mlogger = Substitute.For<ILogger<AesAntiforgery>>();

            var af = new AesAntiforgery(mlogger, TimeSpan.FromHours(12), encryption, cookieSetter);

            var valuesToValidate = af.CreateAntiforgeryTokenSet();

            ctx.Request.Method = "POST";
            ctx.Request.ContentType = "application/json";
            // Add the valid header token.
            ctx.Request.Headers.Add(valuesToValidate.HeaderName, valuesToValidate.RequestToken);
            // Add the valid cookie.
            var cookies = new RequestCookieCollection(new Dictionary<string, string>
            {
                { "csrf_requestid_cookie", valuesToValidate.CookieToken },
            });
            ctx.Request.Cookies = cookies;

            // Act
            var isValid = await af.IsRequestValidAsync(ctx);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public async Task IsRequestValidAsyncRequiresTheCookieToBePresent()
        {
            // Arrange
            var ctx = new DefaultHttpContext();
            var encryption = new NoEncryptionHander();
            var cookieSetter = Substitute.For<ICookieSetter>();
            var mlogger = Substitute.For<ILogger<AesAntiforgery>>();

            var af = new AesAntiforgery(mlogger, TimeSpan.FromHours(12), encryption, cookieSetter);

            var valuesToValidate = af.CreateAntiforgeryTokenSet();

            ctx.Request.Method = "POST";
            ctx.Request.ContentType = "application/json";
            // Add the valid header token.
            ctx.Request.Headers.Add(valuesToValidate.HeaderName, valuesToValidate.RequestToken);
            // Do not add the cookie.

            // Act
            var isValid = await af.IsRequestValidAsync(ctx);

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public async Task IsRequestValidAsyncRequiresTheCookieToBeValid()
        {
            // Arrange
            var ctx = new DefaultHttpContext();
            var encryption = new NoEncryptionHander();
            var cookieSetter = Substitute.For<ICookieSetter>();
            var mlogger = Substitute.For<ILogger<AesAntiforgery>>();

            var af = new AesAntiforgery(mlogger, TimeSpan.FromHours(12), encryption, cookieSetter);

            var valuesToValidate = af.CreateAntiforgeryTokenSet();

            ctx.Request.Method = "POST";
            ctx.Request.ContentType = "application/json";
            // Add the valid header token.
            ctx.Request.Headers.Add(valuesToValidate.HeaderName, valuesToValidate.RequestToken);
            // Add the valid cookie.
            var cookies = new RequestCookieCollection(new Dictionary<string, string>
            {
                { "csrf_requestid_cookie", valuesToValidate.CookieToken + "___" },
            });
            ctx.Request.Cookies = cookies;

            // Act
            var isValid = await af.IsRequestValidAsync(ctx);

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public async Task IsRequestValidAsyncRequiresTheCookieAndSecondaryTokenToMatch()
        {
            // Arrange
            var ctx = new DefaultHttpContext();
            var encryption = new NoEncryptionHander();
            var cookieSetter = Substitute.For<ICookieSetter>();
            var mlogger = Substitute.For<ILogger<AesAntiforgery>>();

            var af1 = new AesAntiforgery(mlogger, TimeSpan.FromHours(12), encryption, cookieSetter);
            var af2 = new AesAntiforgery(mlogger, TimeSpan.FromHours(12), encryption, cookieSetter);

            var validValues1 = af1.CreateAntiforgeryTokenSet();
            var validValues2 = af2.CreateAntiforgeryTokenSet();

            ctx.Request.Method = "POST";
            ctx.Request.ContentType = "application/json";
            // Add the valid header token.
            ctx.Request.Headers.Add(validValues1.HeaderName, validValues1.RequestToken);
            // Add the valid cookie.
            var cookies = new RequestCookieCollection(new Dictionary<string, string>
            {
                { "csrf_requestid_cookie", validValues2.CookieToken },
            });
            ctx.Request.Cookies = cookies;

            // Act
            var isValid = await af1.IsRequestValidAsync(ctx);

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public async Task IsRequestValidAsyncRequiresTheTokenToNotBeExpired()
        {
            // Arrange
            var ctx = new DefaultHttpContext();
            var encryption = new NoEncryptionHander();
            var cookieSetter = Substitute.For<ICookieSetter>();
            var mlogger = Substitute.For<ILogger<AesAntiforgery>>();

            // Set an expired token.
            var af = new AesAntiforgery(mlogger, TimeSpan.FromHours(-12), encryption, cookieSetter);

            var valuesToValidate = af.CreateAntiforgeryTokenSet();

            ctx.Request.Method = "POST";
            ctx.Request.ContentType = "application/json";
            // Add the valid header token.
            ctx.Request.Headers.Add(valuesToValidate.HeaderName, valuesToValidate.RequestToken);
            // Add the valid cookie.
            var cookies = new RequestCookieCollection(new Dictionary<string, string>
            {
                { "csrf_requestid_cookie", valuesToValidate.CookieToken },
            });
            ctx.Request.Cookies = cookies;

            // Act
            var isValid = await af.IsRequestValidAsync(ctx);

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public async Task ValidateRequestAsyncThrowsExceptionsOnInvalidRequests()
        {
            // Arrange
            var ctx = new DefaultHttpContext();
            var encryption = new NoEncryptionHander();
            var cookieSetter = Substitute.For<ICookieSetter>();
            var mlogger = Substitute.For<ILogger<AesAntiforgery>>();

            // Set an expired token.
            var af = new AesAntiforgery(mlogger, TimeSpan.FromHours(-12), encryption, cookieSetter);

            var valuesToValidate = af.CreateAntiforgeryTokenSet();

            ctx.Request.Method = "POST";
            ctx.Request.ContentType = "application/json";
            // Add the valid header token.
            ctx.Request.Headers.Add(valuesToValidate.HeaderName, valuesToValidate.RequestToken);
            // Add the valid cookie.
            var cookies = new RequestCookieCollection(new Dictionary<string, string>
            {
                { "csrf_requestid_cookie", valuesToValidate.CookieToken },
            });
            ctx.Request.Cookies = cookies;

            // Act
            var correctErrorThrown = false;
            try
            {
                await af.ValidateRequestAsync(ctx);
            }
            catch (AntiforgeryValidationException)
            {
                correctErrorThrown = true;
            }

            // Assert
            Assert.True(correctErrorThrown);
        }

         [Fact]
        public async Task ValidateRequestAsyncDoesNotThrowExceptionsOnValidRequests()
        {
            // Arrange
            var ctx = new DefaultHttpContext();
            var encryption = new NoEncryptionHander();
            var cookieSetter = Substitute.For<ICookieSetter>();
            var mlogger = Substitute.For<ILogger<AesAntiforgery>>();

            // Set an expired token.
            var af = new AesAntiforgery(mlogger, TimeSpan.FromHours(12), encryption, cookieSetter);

            var valuesToValidate = af.CreateAntiforgeryTokenSet();

            ctx.Request.Method = "POST";
            ctx.Request.ContentType = "application/json";
            // Add the valid header token.
            ctx.Request.Headers.Add(valuesToValidate.HeaderName, valuesToValidate.RequestToken);
            // Add the valid cookie.
            var cookies = new RequestCookieCollection(new Dictionary<string, string>
            {
                { "csrf_requestid_cookie", valuesToValidate.CookieToken },
            });
            ctx.Request.Cookies = cookies;

            // Act
            var errorThrown = false;
            try
            {
                await af.ValidateRequestAsync(ctx);
            }
            catch (Exception)
            {
                errorThrown = true;
            }

            // Assert
            Assert.False(errorThrown);
        }

        /// <summary>
        /// Used for reviewing failing tests.
        /// </summary>
        public ILogger<AesAntiforgery> CreateConsoleLogger()
        {
            var loggerFactory = new LoggerFactory()
               .AddConsole(LogLevel.Debug)
               .AddDebug();

            return loggerFactory.CreateLogger<AesAntiforgery>();
        }
    }
}
