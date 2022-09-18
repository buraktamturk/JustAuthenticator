using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System;

namespace JustAuthenticator
{
    public class JustAuthenticationConfiguration
    {
        public SecurityKey key;

        public string issuer;

        public string audience;

        public TimeSpan expiration;

        public bool basicAuthentication;

        public Action<AuthorizationOptions> authorizationOptions;

        public Action<AuthenticationOptions> authenticationOptions;
    }
}
