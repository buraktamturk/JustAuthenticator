using System.Security.Claims;
using JustAuthenticator.Abstractions;
using JustAuthenticator.Token;
using System.Threading.Tasks;
using JustAuthenticator.Logging;

namespace JustAuthenticator
{
    internal sealed class TokenEndpointService<TClient, TUser> : ITokenEndpointService
    {
        private readonly IAuthenticatorService<TClient, TUser> service;
        private readonly IPasswordProvider passwordProvider;
        private readonly ICodeProvider codeProvider;
        private readonly IAccessTokenService accessTokenService;
        private readonly JustAuthenticatorMetrics metrics;

        public TokenEndpointService(
            IAuthenticatorService<TClient, TUser> service,
            IPasswordProvider passwordProvider,
            ICodeProvider codeProvider,
            IAccessTokenService accessTokenService,
            JustAuthenticatorMetrics metrics)
        {
            this.service = service;
            this.passwordProvider = passwordProvider;
            this.codeProvider = codeProvider;
            this.accessTokenService = accessTokenService;
            this.metrics = metrics;
        }

        public async Task<TokenResponse> ByExchangeCode(string client_id, string client_secret, string code, string? redirect_uri)
        {
            var client = await service.GetClient(client_id, passwordProvider.Generate(client_secret));
            if(client == null)
                throw new InvalidClientException();
            
            var parsedCode = codeProvider.Parse(code, redirect_uri);
            if (parsedCode == null)
                throw new InvalidGrantException();

            var user = await service.ValidateToken(client, parsedCode, true);
            if (user == null)
                throw new InvalidGrantException();
            
            var claims = await service.MakeClaims(client, user);
            var token = accessTokenService.IssueToken(claims);
            
            var refreshToken = codeProvider.New();
            await service.SaveToken(client, user, refreshToken, false);
            
            metrics.RecordAuthenticationSuccess(claims.FindFirst(ClaimTypes.Role)?.Value);
            
            return token with
            {
                refresh_token = refreshToken.code
            };
        }

        public async Task<TokenResponse> ByRefreshToken(string client_id, string client_secret, string refresh_token)
        {
            var client = await service.GetClient(client_id, passwordProvider.Generate(client_secret));
            if (client == null)
                throw new InvalidClientException();

            var refreshToken = codeProvider.Parse(refresh_token);
            if (refreshToken == null)
                throw new InvalidGrantException();
            
            var user = await service.ValidateToken(client, refreshToken, false);
            if (user == null)
                throw new InvalidGrantException();

            var claims = await service.MakeClaims(client, user);
            var token = accessTokenService.IssueToken(claims);

            metrics.RecordAuthenticationSuccess(claims.FindFirst(ClaimTypes.Role)?.Value);
            
            return token; 
        }

        public async Task<TokenResponse> ByResourceOwnerCredientals(string client_id, string client_secret, string username, string password)
        {
            var client = await service.GetClient(client_id, passwordProvider.Generate(client_secret));
            if(client == null)
                throw new InvalidClientException();

            var user = await service.GetUser(client, username, passwordProvider.Generate(password), true);
            if (user == null)
                throw new InvalidGrantException();

            var claims = await service.MakeClaims(client, user);
            var token = accessTokenService.IssueToken(claims);
            
            var refreshToken = codeProvider.New();
            await service.SaveToken(client, user, refreshToken, false);
            
            metrics.RecordAuthenticationSuccess(claims.FindFirst(ClaimTypes.Role)?.Value);
            
            return token with
            {
                refresh_token = refreshToken.code
            };
        }
    }
}
