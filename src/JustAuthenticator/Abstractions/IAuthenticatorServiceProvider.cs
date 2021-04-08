using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace JustAuthenticator
{
    public interface IAuthenticatorServiceProvider<TClient, TUser>
    {
        ValueTask<IAuthenticatorService<TClient, TUser>> FromContext(HttpContext ctx);
    }
}
