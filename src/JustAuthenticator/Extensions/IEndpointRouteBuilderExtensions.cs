using JustAuthenticator.Abstractions;
using JustAuthenticator.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Text.Json;

namespace JustAuthenticator
{
    public static class IEndpointRouteBuilderExtensions
    {
        public static void MapJustAuthenticator(this IEndpointRouteBuilder that, string path = "/token")
        {
            that.MapPost("/token", async a => {
                var service = a.RequestServices.GetRequiredService<ITokenEndpointService>();

                try { 
                    string client_id = a.Request.Form["client_id"];
                    string client_secret = a.Request.Form["client_secret"];

                    string grant_type = a.Request.Form["grant_type"];

                    var tokenResponse = grant_type switch
                    {
                        "authorization_code" => await service.ByExchangeCode(client_id, client_secret, a.Request.Form["code"], a.Request.Form["redirect_uri"]),
                        "password" => await service.ByResourceOwnerCredientals(client_id, client_secret, a.Request.Form["username"], a.Request.Form["password"]),
                        "refresh_token" => await service.ByRefreshToken(client_id, client_secret, a.Request.Form["refresh_token"]),
                        _ => throw new Exception("invalid_grant"),
                    };

                    if(tokenResponse == null)
                    {
                        throw new OAuth2Exception("invalid_grant");
                    }

                    a.Response.StatusCode = 200;
                    a.Response.ContentType = "application/json; charset=UTF-8";
                    await JsonSerializer.SerializeAsync(a.Response.Body, tokenResponse);
                } catch(OAuth2Exception e) {
                    a.Response.StatusCode = 401;
                    a.Response.ContentType = "application/json; charset=UTF-8";

                    await JsonSerializer.SerializeAsync(a.Response.Body, new OAuth2ErrorResponse
                    {
                        code = e.Message
                    });
                }
            });
        }
    }
}
