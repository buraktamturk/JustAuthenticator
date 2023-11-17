using JustAuthenticator.Abstractions;
using JustAuthenticator.Token;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace JustAuthenticator.Services
{
    public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly IBasicAuthenticationProvider _userService;
        private readonly IPasswordProvider _passwordService;

        
#if !NET8_0_OR_GREATER
        public BasicAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            IBasicAuthenticationProvider userService,
            IPasswordProvider passwordService)
            : base(options, logger, encoder, clock)
        {
            _userService = userService;
            _passwordService = passwordService;
        }
#else
        public BasicAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            IBasicAuthenticationProvider userService,
            IPasswordProvider passwordService)
            : base(options, logger, encoder)
        {
            _userService = userService;
            _passwordService = passwordService;
        }
#endif
        
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var endpoint = Context.GetEndpoint();
            if (endpoint?.Metadata?.GetMetadata<IAllowAnonymous>() != null
                || !Request.Headers.ContainsKey("Authorization")
                || !AuthenticationHeaderValue.TryParse(Request.Headers["Authorization"], out var header)
                || header.Scheme != "Basic")
                return AuthenticateResult.NoResult();

            string username, password;

            try
            {
                var credentialBytes = Convert.FromBase64String(header.Parameter);
                var credentials = Encoding.UTF8.GetString(credentialBytes).Split(new[] { ':' }, 2);
                username = credentials[0];
                password = credentials[1];
            }
            catch
            {
                return AuthenticateResult.Fail("Invalid Authorization Header");
            }

            var identity = await _userService.Authenticate(username, _passwordService.Generate(password));
            if (identity == null)
                return AuthenticateResult.Fail("Invalid Username or Password");

            var ticket = new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(identity.Claims, Scheme.Name)), Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }
    }
}
