using JustAuthenticator.Abstractions;
using JustAuthenticator.Token;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;

namespace JustAuthenticator
{
    public class TokenEndpointService<TClient, TUser> : ITokenEndpointService
    {
        private readonly IAuthenticatorService<TClient, TUser> service;
        private readonly JustAuthenticationConfiguration configuration;
        private readonly JwtSecurityTokenHandler jwtSecurityTokenHandler;
        private readonly SigningCredentials sc;

        private readonly IPasswordProvider passwordProvider;
        private readonly ICodeProvider codeProvider;

        public TokenEndpointService(
            IAuthenticatorService<TClient, TUser> service,
            JustAuthenticationConfiguration configuration,
            SigningCredentials sc,
            IPasswordProvider passwordProvider,
            ICodeProvider codeProvider)
        {
            this.service = service;
            this.configuration = configuration;
            this.sc = sc;
            this.passwordProvider = passwordProvider;
            this.codeProvider = codeProvider;

            this.jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
        }

        public async Task<TokenResponse> ByExchangeCode(string client_id, string client_secret, string code, string redirect_uri)
        {
            var now = DateTime.UtcNow;

            var client = await service.GetClient(client_id, passwordProvider.Generate(client_secret));
            if(client == null)
            {
                throw new OAuth2Exception("invalid_client");
            }

            var user = await service.ValidateToken(client, codeProvider.Parse(code, redirect_uri), true);
            if (user == null)
            {
                throw new OAuth2Exception("invalid_grant");
            }

            var claims = await service.MakeClaims(client, user);

            var access_token = this.jwtSecurityTokenHandler.CreateEncodedJwt(
                issuer: configuration.issuer,
                audience: configuration.audience,
                subject: claims,
                issuedAt: now,
                notBefore: now,
                expires: now + configuration.expiration,
                signingCredentials: sc
            );

            var refreshToken = codeProvider.New();
            await service.SaveToken(client, user, refreshToken, false);

            return new TokenResponse
            {
                access_token = access_token,
                expires_in = 3599,
                token_type = "Bearer",
                refresh_token = refreshToken.code
            };
        }

        public async Task<TokenResponse> ByRefreshToken(string client_id, string client_secret, string refresh_token)
        {
            var now = DateTime.UtcNow;

            var client = await service.GetClient(client_id, passwordProvider.Generate(client_secret));
            if (client == null)
            {
                throw new OAuth2Exception("invalid_client");
            }

            var refreshToken = codeProvider.Parse(refresh_token);
            var user = await service.ValidateToken(client, refreshToken, false);
            if (user == null)
            {
                throw new OAuth2Exception("invalid_grant");
            }

            var claims = await service.MakeClaims(client, user);

            var access_token = this.jwtSecurityTokenHandler.CreateEncodedJwt(
                issuer: configuration.issuer,
                audience: configuration.audience,
                subject: claims,
                issuedAt: now,
                notBefore: now,
                expires: now + configuration.expiration,
                signingCredentials: sc
            );

            return new TokenResponse
            {
                access_token = access_token,
                expires_in = 3599,
                token_type = "Bearer",
                refresh_token = refreshToken.code
            };
        }

        public async Task<TokenResponse> ByResourceOwnerCredientals(string client_id, string client_secret, string username, string password)
        {
            var now = DateTime.UtcNow;

            var client = await service.GetClient(client_id, passwordProvider.Generate(client_secret));
            if(client == null)
            {
                throw new OAuth2Exception("invalid_client");
            }

            var user = await service.GetUser(client, username, passwordProvider.Generate(password), true);
            if (user == null)
            {
                throw new OAuth2Exception("invalid_grant");
            }

            var claims = await service.MakeClaims(client, user);

            var access_token = this.jwtSecurityTokenHandler.CreateEncodedJwt(
                issuer: configuration.issuer,
                audience: configuration.audience,
                subject: claims,
                issuedAt: now,
                notBefore: now,
                expires: now + configuration.expiration,
                signingCredentials: sc
            );

            var refreshToken = codeProvider.New();
            await service.SaveToken(client, user, refreshToken, false);

            return new TokenResponse
            {
                access_token = access_token,
                expires_in = 3599,
                token_type = "Bearer",
                refresh_token = refreshToken.code
            };
        }
    }
}
