using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using JustAuthenticator.Abstractions;
using Microsoft.IdentityModel.Tokens;

namespace JustAuthenticator.Services;

public class AccessTokenService : IAccessTokenService
{
    private readonly JustAuthenticationConfiguration configuration;
    private readonly JwtSecurityTokenHandler jwtSecurityTokenHandler;
    private readonly SigningCredentials sc;

    public AccessTokenService(JustAuthenticationConfiguration configuration, SigningCredentials sc)
    {
        this.configuration = configuration;
        this.sc = sc;
        this.jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
    }

    public TokenResponse IssueToken(ClaimsIdentity claims)
    {
        var now = DateTime.UtcNow;
        
        var accessToken = this.jwtSecurityTokenHandler.CreateEncodedJwt(
            issuer: configuration.issuer,
            audience: configuration.audience,
            subject: claims,
            issuedAt: now,
            notBefore: now,
            expires: now + configuration.expiration,
            signingCredentials: sc
        );

        return new TokenResponse(accessToken, "Bearer", (int)Math.Floor(configuration.expiration.TotalSeconds) - 1);
    }
}