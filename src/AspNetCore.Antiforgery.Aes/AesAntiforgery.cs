using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Microsoft.Extensions.Logging;

namespace AspNetCore.Antiforgery.Aes
{
    public class AesAntiforgery : IAntiforgery
    {
        /// <summary>
        /// The name of the form field added to HTTP forms to store the plaintext token.
        /// </summary>
        public static string FORM_FIELD_NAME = "csrf_requestid";

        /// <summary>
        /// The name of the session cookie used to store the encrypted csrf token.
        /// </summary>
        public static string COOKIE_NAME = "csrf_requestid_cookie";

        /// <summary>
        /// The name of the HTTP header used in place of the form field name for JSON posts.
        /// </summary>
        public static string HEADER_NAME = "X-Csrf-RequestId";

        private readonly TimeSpan _duration;
        private readonly ILogger<AesAntiforgery> _logger;
        private readonly IEncryptionHandler _encryption;

        /// <summary>
        /// Stores antiforgery tokens generated in the current HTTP request so that they're reused across
        /// a single HTTP GET request.
        /// </summary>
        private AntiforgeryTokenSet _storedAntiforgeryTokenSet = null;
        private readonly ICookieSetter _cookieSetter;

        /// <summary>
        /// Creates an instance of the AesAntiforgery type using the environment variables to collect keys.
        /// </summary>
        /// <param name="logger">A logger used to write detailed log entries.</param>
        /// <param name="duration">The maximum duration of the CSRF token, after this period it will be rejected e.g. after 12 hours.</param>
        public AesAntiforgery(ILogger<AesAntiforgery> logger, TimeSpan duration)
            : this(logger, new EnvironmentSettingProvider(), duration)
        {
        }

        /// <summary>
        /// Creates an instance of the AesAntiforgery type.
        /// </summary>
        /// <param name="logger">A logger used to write detailed log entries.</param>
        /// <param name="key">The key used for AES encryption.</param>
        /// <param name="iv">The iv for AES encrytpion.</param>
        /// <param name="duration">The maximum duration of the CSRF token, after this period it will be rejected e.g. after 12 hours.</param>
        public AesAntiforgery(ILogger<AesAntiforgery> logger, byte[] key, byte[] iv, TimeSpan duration)
            : this(logger, new StaticSettingProvider(key, iv), duration)
        {
        }

        /// <summary>
        /// Creates an instance of the AesAntiforgery type.
        /// </summary>
        /// <param name="logger">A logger used to write detailed log entries.</param>
        /// <param name="settings">The key and IV used for AES encryption.</param>
        /// <param name="duration">The maximum duration of the CSRF token, after this period it will be rejected e.g. after 12 hours.</param>
        public AesAntiforgery(ILogger<AesAntiforgery> logger, ISettingProvider settings, TimeSpan duration)
            : this(logger, duration, new EncryptionHandler(settings.Key, settings.IV), new CookieSetter())
        {
        }

        /// <summary>
        /// Creates an instance of the AesAntiforgery type.
        /// </summary>
        /// <param name="logger">A logger used to write detailed log entries.</param>
        /// <param name="duration">The maximum duration of the CSRF token, after this period it will be rejected e.g. after 12 hours.</param> <summary>
        /// <param name="encryption">An implementation of basic symmetric encryption and decryption.</param>
        public AesAntiforgery(ILogger<AesAntiforgery> logger, TimeSpan duration, IEncryptionHandler encryption, ICookieSetter cookieSetter)
        {
            _logger = logger;
            _duration = duration;
            _encryption = encryption;
            _cookieSetter = cookieSetter;
        }

        /// <inheritdoc />
        public AntiforgeryTokenSet GetAndStoreTokens(HttpContext httpContext)
        {
            _logger.LogDebug("GetAndStoreTokens {method}", httpContext.Request.Method);

            // Set required headers.
            httpContext.Response.Headers.Add("Cache-control", "no-cache");
            httpContext.Response.Headers.Add("Pragma", "no-cache");
            httpContext.Response.Headers.Add("X-Frame-Options", "SAMEORIGIN");

            var tokenSet = GetTokens(httpContext);

            // Set the cookie with the encrypted value of the guid.
            _logger.LogDebug("Setting request cookie");
            _cookieSetter.Set(httpContext.Response.Cookies, COOKIE_NAME, tokenSet.CookieToken);
            return tokenSet;
        }

        /// <inheritdoc />
        public AntiforgeryTokenSet GetTokens(HttpContext httpContext)
        {
            if (_storedAntiforgeryTokenSet == null)
            {
                _logger.LogDebug("GetTokens - creating new tokens");
                _storedAntiforgeryTokenSet = CreateAntiforgeryTokenSet();
            }
            else
            {
                _logger.LogDebug("GetTokens - reusing existing tokens");
            }

            return _storedAntiforgeryTokenSet;
        }

        /// <inheritdoc />
        public Task<bool> IsRequestValidAsync(HttpContext httpContext)
        {
            _logger.LogDebug("IsRequestValidAsync");

            var method = httpContext.Request.Method;
            if (string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(method, "HEAD", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(method, "OPTIONS", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(method, "TRACE", StringComparison.OrdinalIgnoreCase))
            {
                // Validation not needed for these request types.
                _logger.LogDebug("IsRequestValidAsync returned true because its a GET, HEAD, OPTIONS or TRACE request.");
                return Task.FromResult<bool>(true);
            }

            // Find out whether we've got the cookie value, the cookie is essential.
            RequestToken cookieToken;
            var hasCookieToken = TryGetTokenFromCookie(httpContext.Request.Cookies, out cookieToken);

            if (!hasCookieToken)
            {
                _logger.LogDebug("IsRequestValidAsync returned false because the cookie value was not set or was invalid.");
                return Task.FromResult<bool>(false);
            }

            // We can then accept either a HTTP request header (for Ajax requests) or a form value.
            RequestToken secondaryToken;
            var hasReceivedSecondaryToken = TryGetTokenFromHeader(httpContext.Request.Headers, out secondaryToken);

            if (!hasReceivedSecondaryToken)
            {
                if (!httpContext.Request.HasFormContentType)
                {
                    _logger.LogDebug("IsRequestValidAsync returned false because the HTTP request does not have the correct form content type to receive a form post.");
                    return Task.FromResult<bool>(false);
                }

                hasReceivedSecondaryToken = TryGetTokenFromForm(httpContext.Request.Form, out secondaryToken);
            }

            if (!hasReceivedSecondaryToken)
            {
                _logger.LogDebug("IsRequestValidAsync returned false because a CSRF HTTP form value or HTTP header was not set.");
                return Task.FromResult<bool>(false);
            }

            if (cookieToken.Guid != secondaryToken.Guid)
            {
                _logger.LogDebug("IsRequestValidAsync returned false because the cookieToken id didn't match the secondary token id.");
                return Task.FromResult<bool>(false);
            }

            // The cookieToken is encrypted, so use that.
            var hasExpired = cookieToken.HasExpired;

            if (hasExpired)
            {
                _logger.LogDebug("IsRequestValidAsync returned false because the token has expired.");
                return Task.FromResult<bool>(false);
            }

            _logger.LogDebug("IsRequestValidAsync returned true because no problems were found.");
            return Task.FromResult<bool>(true);
        }

        /// <inheritdoc />
        public void SetCookieTokenAndHeader(HttpContext httpContext)
        {
            _logger.LogDebug("SetCookieTokenAndHeader");
            GetAndStoreTokens(httpContext);
        }

        /// <inheritdoc />
        public async Task ValidateRequestAsync(HttpContext httpContext)
        {
            _logger.LogDebug("ValidateRequestAsync");

            var isValid = await IsRequestValidAsync(httpContext);

            if (!isValid)
            {
                throw new AntiforgeryValidationException("The request is not valid.");
            }
        }

        public AntiforgeryTokenSet CreateAntiforgeryTokenSet()
        {
            var requestId = new RequestToken(_duration);
            var encrypted = _encryption.Encrypt(requestId.ToString());

            // Set the form field to be the unencrypted value of the value, while the cookie
            // is the encrypted value.
            return new AntiforgeryTokenSet(requestId.ToString(), encrypted, FORM_FIELD_NAME, HEADER_NAME);
        }

        private bool TryGetTokenFromCookie(IRequestCookieCollection cookies, out RequestToken token)
        {
            string cookieValue;
            if (cookies.TryGetValue(COOKIE_NAME, out cookieValue))
            {
                cookieValue = _encryption.Decrypt(cookieValue);
            }
            var hasCookieValue = !string.IsNullOrWhiteSpace(cookieValue);
            if (!hasCookieValue)
            {
                token = null;
                return false;
            }
            return RequestToken.TryParse(cookieValue, out token);
        }

        private bool TryGetTokenFromForm(IFormCollection form, out RequestToken token)
        {
            StringValues formValue;
            var hasFormValue = form.TryGetValue(FORM_FIELD_NAME, out formValue) &&
                !string.IsNullOrWhiteSpace(formValue);
            if (!hasFormValue)
            {
                token = null;
                return false;
            }
            return RequestToken.TryParse(formValue, out token);
        }

        private bool TryGetTokenFromHeader(IHeaderDictionary headers, out RequestToken token)
        {
            StringValues headerValue;
            var hasHeaderValue = headers.TryGetValue(HEADER_NAME, out headerValue) &&
                !string.IsNullOrWhiteSpace(headerValue);
            if (!hasHeaderValue)
            {
                token = null;
                return false;
            }
            return RequestToken.TryParse(headerValue, out token);
        }
    }
}