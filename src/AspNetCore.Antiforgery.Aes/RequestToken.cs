using System;

namespace AspNetCore.Antiforgery.Aes
{
    public class RequestToken
    {
        public RequestToken(TimeSpan expiry) : this(() => DateTime.UtcNow, Guid.NewGuid(), expiry)
        {
        }

        public RequestToken(Func<DateTime> dateTimeProvider, Guid g, TimeSpan expiry)
        {
            this.DateTimeProvider = dateTimeProvider;
            this.Guid = g;
            this.Expiry = DateTimeProvider().Add(expiry);
        }

        public RequestToken(string s) : this(() => DateTime.UtcNow, s)
        {
        }

        public RequestToken(Func<DateTime> dateTimeProvider, string s)
        {
            if (string.IsNullOrWhiteSpace(s))
            {
                throw new ArgumentException("s cannot be null or empty");
            }

            var parts = s.Split('_');

            if (parts.Length != 2)
            {
                throw new ArgumentException("s must consist of a guid and ticks number seperated by an underscore");
            }

            this.DateTimeProvider = dateTimeProvider;
            this.Guid = Guid.Parse(parts[0]);
            this.Expiry = new DateTime(long.Parse(parts[1]), DateTimeKind.Utc);
        }

        public new string ToString()
        {
            return this.Guid.ToString() + "_" + this.Expiry.Ticks.ToString();
        }

        public static bool TryParse(string value, out RequestToken token)
        {
            try
            {
                token = new RequestToken(value);
            }
            catch (Exception)
            {
                token = null;
                return false;
            }

            return true;
        }

        public Guid Guid { get; set; }
        public DateTime Expiry { get; set; }
        public Func<DateTime> DateTimeProvider = () => DateTime.UtcNow;

        public bool HasExpired
        {
            get
            {
                return DateTimeProvider() > this.Expiry;
            }
        }
    }
}