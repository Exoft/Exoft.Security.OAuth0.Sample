using System;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SimpleTokenProvider.Test;
using SimpleTokenProvider.Test.Models;

namespace SimpleTokenProvider.Sample
{
    public partial class Startup
    {
        // The secret key every token will be signed with.
        // Keep this safe on the server!
        private static readonly string secretKey = "9565DF9A29045887BBA658ED322D8735C28F239A76041C20C0C851ED90D28B71";
        private static readonly string secretKey2 = "d8e60aa3-1c45-4b54-8b4e-108571918149";

        private void ConfigureAuth(IApplicationBuilder app, DemoDb db, ILoggerFactory loggerFactory)
        {

            app.UseSimpleTokenProvider(new TokenProviderOptions
            {
                Path = "/token",
                Audience = "ExampleAudience",
                Issuer = "ExampleIssuer",
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey)), SecurityAlgorithms.HmacSha256),
                SigningRTokenCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey2)), SecurityAlgorithms.HmacSha256),
                IdentityResolver = GetIdentity,
                ExpirationAccessToken = TimeSpan.FromMinutes(10),
                ExpirationRefreshToken = TimeSpan.FromMinutes(1),
                GetRefreshTokenResolver = (options) => GetRefreshToken(options, db),
                AddRefreshTokenResolver = (options) => AddRefreshToken(options, db),
                ValidateClientResolver = (clientId, clientSecret) => ValidateClient(clientId, clientSecret, db)
            });

            app.UseAuthentication();
        }

        private Task<ClaimsIdentity> GetIdentity(string username, string password)
        {
            // Don't do this in production, obviously!
            if (username == "demo@demo.com" && password == "demodemo")
            {
                // get user from db
                return Task.FromResult(new ClaimsIdentity(new GenericIdentity(username, "Token"), new Claim[]{ new Claim(ClaimTypes.Role, "ExoftAdmin") }));
            }

            // Credentials are invalid, or account doesn't exist
            return Task.FromResult<ClaimsIdentity>(null);
        }

        private bool ValidateClient(string clientId, string clientSecret, DemoDb dbContext)
        {
            /* Validated client_id/client_secret
             * 
             * var isValidated = dbContext.Users.Any(x => x.ClientId && x.ClientSecret == clientSecret);
             *
             * return isValidated;
             */
            return true;
        }

        private bool AddRefreshToken(RefreshTokenDto options, DemoDb dbContext)
        {
            dbContext.Add(new RefreshToken()
            {
                ExpirationRefreshToken = options.ExpirationRefreshToken,
                Token = options.RefreshToken,
                ClientId = options.ClientId
            });

            return dbContext.SaveChanges() > 0;
        }

        private RefreshTokenDto GetRefreshToken(RefreshTokenDto options, DemoDb dbContext)
        {
            RefreshToken token;
            if (!string.IsNullOrEmpty(options.ClientId))
            {
                token = dbContext.RefreshTokens.FirstOrDefault(x => x.Token == options.RefreshToken && x.ClientId == options.ClientId);
            }
            else
            {
                token = dbContext.RefreshTokens.FirstOrDefault(x => x.Token == options.RefreshToken);
            }

            if (token != null)
            {
                return options;
            }
            return null;
        }
    }
}
