using System.Threading.Tasks;

namespace JustAuthenticator.Abstractions
{
    public interface ITokenEndpointService
    {
        Task<TokenResponse> ByExchangeCode(string client_id, string client_secret, string code, string redirect_uri);
        Task<TokenResponse> ByRefreshToken(string client_id, string client_secret, string refresh_token);
        Task<TokenResponse> ByResourceOwnerCredientals(string client_id, string client_secret, string username, string password);
    }
}
