using Microsoft.AspNetCore.Authentication.JwtBearer;
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

            that
                .AddSingleton(configuration)
                .AddSingleton(configuration.key)
                .AddSingleton(new SigningCredentials(configuration.key, SecurityAlgorithms.HmacSha512))
                .AddAuthentication(x =>
                {
                    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddJwtBearer(x =>
                {
                    x.RequireHttpsMetadata = false;
                    x.SaveToken = true;
                    x.TokenValidationParameters = parameters;
                });
             
            return that;
        } 
    }
}
