using System;
using Xunit;

namespace AspNetCore.Antiforgery.Aes.Tests
{
    public class RequestTokenTests
    {
        [Fact]
        public void RequestTokensCanBeSerializedAndDeserialized()
        {
            var year2000 = new DateTime(2000, 1, 1);
            var provider = new Func<DateTime>(() => year2000);
            var guid = Guid.NewGuid();
            var token = new RequestToken(provider, guid, TimeSpan.Zero);

            Assert.Equal(guid.ToString() + "_" + year2000.Ticks.ToString(), token.ToString());

            var deserialized = new RequestToken(provider, token.ToString());

            Assert.Equal(token.Guid, deserialized.Guid);
            Assert.Equal(token.Expiry, deserialized.Expiry);
        }

        [Fact]
        public void RequestTokensCanExpire()
        {
            var year2000 = new DateTime(2000, 1, 1);
            var provider = new Func<DateTime>(() => year2000);
            var guid = Guid.NewGuid();

            var tokenA = new RequestToken(provider, guid, TimeSpan.FromHours(-1));
            Assert.Equal(tokenA.HasExpired, true);

            var tokenB = new RequestToken(provider, guid, TimeSpan.FromHours(+1));
            Assert.Equal(tokenB.HasExpired, false);
        }

        [Fact]
        public void ItIsPossibleToTryParsingTokens()
        {
            var year2000 = new DateTime(2000, 1, 1);
            var provider = new Func<DateTime>(() => year2000);
            var guid = Guid.NewGuid();

            RequestToken token;
            var resultA = RequestToken.TryParse("dsfsdfsdfsf", out token);
            var resultB = RequestToken.TryParse("6f607edf-5543-4ca8-a087-6dc857f06801_630822816000000000", out token);

            Assert.False(resultA);
            Assert.True(resultB);
        }
    }
}