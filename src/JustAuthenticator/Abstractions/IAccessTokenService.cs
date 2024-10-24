using System.Security.Claims;

namespace JustAuthenticator.Abstractions;

public interface IAccessTokenService
{
    TokenResponse IssueToken(ClaimsIdentity claims);
}