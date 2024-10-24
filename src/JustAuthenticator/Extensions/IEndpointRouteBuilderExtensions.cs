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
using System.Threading.Tasks;
using JustAuthenticator.Logging;
using JustAuthenticator.Services;

namespace JustAuthenticator
{
    public static class IEndpointRouteBuilderExtensions
    {
        private static async Task<IResult> Process(HttpRequest request, ITokenEndpointService service)
        {
            var metrics = request.HttpContext.RequestServices.GetRequiredService<JustAuthenticatorMetrics>();
            try
            {
                string? clientId, clientSecret;

                if (request.Headers.TryGetValue("Authorization", out var strAuthorization)
                    && strAuthorization.FirstOrDefault(header => header?.StartsWith("Basic ") == true) is {} auth)
                {
                    var data = Encoding.UTF8.GetString(Convert.FromBase64String(auth["Basic ".Length..]))
                        .Split(':');

                    clientId = data[0];
                    clientSecret = data[1];
                }
                else
                {
                    clientId = request.Form["client_id"];
                    clientSecret = request.Form["client_secret"];
                }

                if (clientId is null || clientSecret is null)
                    throw new InvalidClientException();
                
                string? grantType = request.Form["grant_type"];
                var token = grantType switch
                {
                    "authorization_code" => await service.ByExchangeCode(
                        clientId,
                        clientSecret,
                        request.Form["code"].FirstOrDefault()
                            ?? throw new OAuth2Exception("invalid_request", "Code is required"), 
                        request.Form["redirect_uri"]
                    ),
                    "password" => await service.ByResourceOwnerCredientals(
                        clientId,
                        clientSecret, 
                        request.Form["username"].FirstOrDefault()
                                      ?? throw new OAuth2Exception("invalid_request", "Username is required"),
                        request.Form["password"].FirstOrDefault()
                            ?? throw new OAuth2Exception("invalid_request", "Password is required")
                    ),
                    "refresh_token" => await service.ByRefreshToken(
                        clientId,
                        clientSecret,
                        request.Form["refresh_token"].FirstOrDefault()
                            ?? throw new OAuth2Exception("invalid_request", "Refresh token is required")),
                    _ => throw new UnsupportedGrantTypeException(),
                };

                if (token == null)
                    throw new InvalidGrantException();

                return Results.Json(token, SourceGenerationContext.Default.TokenResponse);
            }
            catch (OAuth2Exception e)
            {
                metrics.RecordAuthenticationError(e.Error);
                return Results.Json(new OAuth2ErrorResponse(e.Error, e.ErrorDescription),
                    SourceGenerationContext.Default.OAuth2ErrorResponse, statusCode: e is InvalidClientException or InvalidGrantException ? 401 : 400);
            }
        }

        public static IEndpointConventionBuilder MapJustAuthenticator(this IEndpointRouteBuilder that, string path = "/token")
        {
            return that.MapPost(path, async (HttpRequest request) => {
                var service = request.HttpContext.RequestServices.GetRequiredService<ITokenEndpointService>();
                return await Process(request, service);
            });
        }

        public static IEndpointConventionBuilder MapJustAuthenticator<TAuthenticatorServiceProvider, TClient, TUser>(this IEndpointRouteBuilder that, string path = "/token")
            where TAuthenticatorServiceProvider : IAuthenticatorServiceProvider<TClient, TUser>
        {
            return that.MapPost(path, async (HttpRequest request) => {
                var service = request.HttpContext.RequestServices.GetRequiredService<TAuthenticatorServiceProvider>();
                var srv = await service.FromContext(request.HttpContext);
                
                return await Process(request, new TokenEndpointService<TClient, TUser>(
                    srv,
                    request.HttpContext.RequestServices.GetRequiredService<IPasswordProvider>(),
                    request.HttpContext.RequestServices.GetRequiredService<ICodeProvider>(),
                    request.HttpContext.RequestServices.GetRequiredService<IAccessTokenService>(),
                    request.HttpContext.RequestServices.GetRequiredService<JustAuthenticatorMetrics>()
                ));
            });
        }
    }
}
