using JustAuthenticator.Token;
using System.Security.Claims;
using System.Threading.Tasks;

namespace JustAuthenticator.Abstractions
{
    public interface IBasicAuthenticationProvider
    {
        Task<ClaimsIdentity?> Authenticate(string username, IPassword password);
    }
}
