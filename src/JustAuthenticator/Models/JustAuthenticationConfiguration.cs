using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System;

namespace JustAuthenticator
{
    public class JustAuthenticationConfiguration
    {
        public SecurityKey key;

        public string? issuer;

        public string? audience;

        public TimeSpan expiration;

        public bool basicAuthentication;

        public Action<AuthorizationOptions>? authorizationOptions;

        public Action<AuthenticationOptions>? authenticationOptions;

        public JustAuthenticationConfiguration(SecurityKey key, string? audience, string? issuer, TimeSpan expiration, bool basicAuthentication, Action<AuthenticationOptions>? authenticationOptions, Action<AuthorizationOptions>? authorizationOptions)
        {
            this.key = key;
            this.audience = audience;
            this.issuer = issuer;
            this.expiration = expiration;
            this.basicAuthentication = basicAuthentication;
            this.authenticationOptions = authenticationOptions;
            this.authorizationOptions = authorizationOptions;
        }
    }
}
