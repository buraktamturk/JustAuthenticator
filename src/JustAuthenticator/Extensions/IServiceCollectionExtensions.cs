using JustAuthenticator.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace JustAuthenticator
{
    public static class IServiceCollectionExtensions
    {
        public static IServiceCollection AddJustAuthenticator(this IServiceCollection that, Action<JustAuthenticationBuilder> options)
        {
            var builder = new JustAuthenticationBuilder(that);

            options(builder);

            JustAuthenticationConfiguration configuration = builder.Build();

            var parameters = new TokenValidationParameters
            {
                ValidateAudience = configuration.audience != null,
                ValidateIssuer = configuration.issuer != null,
                ValidIssuer = configuration.issuer,
                ValidAudience = configuration.audience,
                IssuerSigningKey = configuration.key
            };

            var auth = that
                .AddSingleton(configuration)
                .AddSingleton(configuration.key)
                .AddSingleton(new SigningCredentials(configuration.key, SecurityAlgorithms.HmacSha512))
                .AddAuthorization(options =>
                {
                    var defaultAuthorizationPolicyBuilder = configuration.basicAuthentication ? new AuthorizationPolicyBuilder(
                        "Basic",
                        JwtBearerDefaults.AuthenticationScheme
                    ) : new AuthorizationPolicyBuilder(JwtBearerDefaults.AuthenticationScheme);

                    defaultAuthorizationPolicyBuilder =
                        defaultAuthorizationPolicyBuilder.RequireAuthenticatedUser();

                    options.DefaultPolicy = defaultAuthorizationPolicyBuilder.Build();

                    configuration.authorizationOptions?.Invoke(options);
                })
                .AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

                    configuration.authenticationOptions?.Invoke(options);
                })
                .AddJwtBearer(x =>
                {
                    x.RequireHttpsMetadata = false;
                    x.SaveToken = true;
                    x.TokenValidationParameters = parameters;
                });

            if (configuration.basicAuthentication)
            {
                auth.AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>("Basic", null);
            }
             
            return that;
        } 
    }
}
