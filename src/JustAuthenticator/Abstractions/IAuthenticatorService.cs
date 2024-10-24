using JustAuthenticator.Token;
using System.Security.Claims;
using System.Threading.Tasks;

namespace JustAuthenticator
{
    public interface IAuthenticatorService<TClient, TUser>
    {
        Task<TClient?> GetClient(string client_id, IPassword client_secret);
        Task<TUser?> GetUser(TClient client, string username, IPassword password, bool trusted);
        Task<ClaimsIdentity> MakeClaims(TClient client, TUser user);
        Task SaveToken(TClient client, TUser user, ICode token, bool disposable);
        Task<TUser?> ValidateToken(TClient client, ICode token, bool dispose);
    }
}
