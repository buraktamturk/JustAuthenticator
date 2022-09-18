using JustAuthenticator.Abstractions;
using JustAuthenticator.Token;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Text;

namespace JustAuthenticator
{
    public class JustAuthenticationBuilder
    {
        private readonly IServiceCollection _serviceCollection;

        private SecurityKey key;

        public string audience;

        public string issuer;

        private TimeSpan expiration = TimeSpan.FromHours(1);

        private bool passwordProviderAdded = false;

        private bool codeProviderAdded = false;

        private bool basicAuthenticationProviderAdded = false;

        private Action<AuthorizationOptions> authorizationOptions;

        private Action<AuthenticationOptions> authenticationOptions;

        public JustAuthenticationBuilder(IServiceCollection serviceCollection)
        {
            this._serviceCollection = serviceCollection;
        }

        public JustAuthenticationBuilder UseKey(SecurityKey key)
        {
            this.key = key;
            return this;
        }

        public JustAuthenticationBuilder UseSymmetricKey(byte[] key)
        {
            return UseKey(new SymmetricSecurityKey(key));
        }

        public JustAuthenticationBuilder UseSymmetricKey(string key)
        {
            return UseKey(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(key)));
        }

        public JustAuthenticationBuilder SetAudience(string audience)
        {
            this.audience = audience;
            return this;
        }

        public JustAuthenticationBuilder SetIssuer(string issuer)
        {
            this.issuer = issuer;
            return this;
        }

        public JustAuthenticationBuilder SetExpiration(TimeSpan expiration)
        {
            this.expiration = expiration;
            return this;
        }

        public JustAuthenticationBuilder AddBasicAuthentication<T>() where T : class, IBasicAuthenticationProvider
        {
            basicAuthenticationProviderAdded = true;

            this._serviceCollection
                .AddScoped<IBasicAuthenticationProvider, T>();

            return this;
        }

        public JustAuthenticationBuilder AddPasswordProvider<T>() where T : class, IPasswordProvider
        {
            passwordProviderAdded = true;

            this._serviceCollection
                .AddSingleton<IPasswordProvider, T>();

            return this;
        }

        public JustAuthenticationBuilder AddCodeProvider<T>() where T : class, ICodeProvider
        {
            codeProviderAdded = true;

            this._serviceCollection
                .AddSingleton<ICodeProvider, T>();

            return this;
        }

        public JustAuthenticationBuilder UseHandler<T, TClient, TUser>() where T : class, IAuthenticatorService<TClient, TUser>
        {
            _serviceCollection
                .AddScoped<IAuthenticatorService<TClient, TUser>, T>()
                .AddScoped<ITokenEndpointService, TokenEndpointService<TClient, TUser>>();

            return this;
        }

        public JustAuthenticationBuilder UseProvider<T, TClient, TUser>() where T : class, IAuthenticatorServiceProvider<TClient, TUser>
        {
            _serviceCollection
                .AddScoped<T>();

            return this;
        }

        public JustAuthenticationBuilder UseAuthorizationOptions(Action<AuthorizationOptions> options)
        {
            this.authorizationOptions = options;
            return this;
        }

        public JustAuthenticationBuilder UseAuthenticationOptions(Action<AuthenticationOptions> options)
        {
            this.authenticationOptions = options;
            return this;
        }

        public JustAuthenticationConfiguration Build()
        {
            if (!passwordProviderAdded)
                _serviceCollection
                    .AddSingleton<IPasswordProvider, DefaultPasswordProvider>();

            if (!codeProviderAdded)
                _serviceCollection
                    .AddSingleton<ICodeProvider, DefaultCodeProvider>();

            return new JustAuthenticationConfiguration()
            {
                key = key,
                audience = audience,
                issuer = issuer,
                expiration = expiration,
                basicAuthentication = basicAuthenticationProviderAdded,
                authenticationOptions = authenticationOptions,
                authorizationOptions = authorizationOptions
            };
        }
    }
}
