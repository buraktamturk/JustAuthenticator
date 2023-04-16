using System;
using System.Linq;
using System.Text;
using JustAuthenticator.Abstractions;
using JustAuthenticator.Models;
using JustAuthenticator.Token;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;
using System.Threading.Tasks;

namespace JustAuthenticator
{
    public static class IEndpointRouteBuilderExtensions
    {
        private static async Task Process(HttpContext a, ITokenEndpointService service)
        {
            try
            {
                string client_id,
                    client_secret;

                if (a.Request.Headers.TryGetValue("Authorization", out var strAuthorization)
                    && strAuthorization.FirstOrDefault() is {} auth && auth.StartsWith("Basic "))
                {
                    var data = Encoding.UTF8.GetString(Convert.FromBase64String(auth["Basic ".Length..]))
                        .Split(':');

                    client_id = data[0];
                    client_secret = data[1];
                }
                else
                {
                    client_id = a.Request.Form["client_id"];
                    client_secret = a.Request.Form["client_secret"];
                }
                
                string grant_type = a.Request.Form["grant_type"];

                var tokenResponse = grant_type switch
                {
                    "authorization_code" => await service.ByExchangeCode(client_id, client_secret, a.Request.Form["code"], a.Request.Form["redirect_uri"]),
                    "password" => await service.ByResourceOwnerCredientals(client_id, client_secret, a.Request.Form["username"], a.Request.Form["password"]),
                    "refresh_token" => await service.ByRefreshToken(client_id, client_secret, a.Request.Form["refresh_token"]),
                    _ => throw new OAuth2Exception("unsupported_grant_type"),
                };

                if (tokenResponse == null)
                {
                    throw new OAuth2Exception("invalid_grant");
                }

                a.Response.StatusCode = 200;
                a.Response.ContentType = "application/json; charset=UTF-8";
                await JsonSerializer.SerializeAsync(a.Response.Body, tokenResponse);
            }
            catch (OAuth2Exception e)
            {
                a.Response.StatusCode = 401;
                a.Response.ContentType = "application/json; charset=UTF-8";

                await JsonSerializer.SerializeAsync(a.Response.Body, new OAuth2ErrorResponse
                {
                    code = e.Message
                });
            }
        }

        public static IEndpointConventionBuilder MapJustAuthenticator(this IEndpointRouteBuilder that, string path = "/token")
        {
            return that.MapPost(path, async ctx => {
                var service = ctx.RequestServices.GetRequiredService<ITokenEndpointService>();
                await Process(ctx, service);
            });
        }

        public static IEndpointConventionBuilder MapJustAuthenticator<X, TClient, TUser>(this IEndpointRouteBuilder that, string path = "/token") where X : IAuthenticatorServiceProvider<TClient, TUser>
        {
            return that.MapPost(path, async ctx => {
                var service = ctx.RequestServices.GetRequiredService<X>();
                var srv = await service.FromContext(ctx);
                await Process(ctx, new TokenEndpointService<TClient, TUser>(
                    srv,
                    ctx.RequestServices.GetRequiredService<JustAuthenticationConfiguration>(),
                    ctx.RequestServices.GetRequiredService<SigningCredentials>(),
                    ctx.RequestServices.GetRequiredService<IPasswordProvider>(),
                    ctx.RequestServices.GetRequiredService<ICodeProvider>()
                ));
            });
        }
    }
}
