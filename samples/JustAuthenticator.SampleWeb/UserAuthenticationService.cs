using JustAuthenticator.Token;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace JustAuthenticator.SampleWeb
{
    public class Client
    {

    }

    public class User
    {

    }

    public class UserAuthenticationService : IAuthenticatorService<Client, User>
    {
        public static Dictionary<Guid, (string hash, bool disposable, User user)> passwords = new Dictionary<Guid, (string hash, bool disposable, User user)>();

        public async Task<Client> GetClient(string client_id, IPassword client_secret)
        {
            if (client_id != "test")
            {
                throw new OAuth2Exception("invalid_grant");
            }

            return new Client() { };
        }

        public async Task<User> GetUser(Client client, string username, IPassword password, bool trusted)
        {
            if(username != "test")
            {
                throw new OAuth2Exception("invalid_grant");
            }

            if(!password.Compare(password.Hashed))
            {
                throw new OAuth2Exception("invalid_grant");
            }

            return new User()
            {

            };
        }

        public async Task<ClaimsIdentity> MakeClaims(Client client, User user)
        {
            var claims = new ClaimsIdentity();

            return claims;
        }

        public Task SaveToken(Client client, User user, ICode token, bool disposable)
        {
            passwords[token_id] = token.Hashed;
            return Task.CompletedTask;
        }

        public Task<User> ValidateToken(Client client, ICode token, bool dispose)
        {
            passwords.ContainsKey(token_id);



        }
    }
}
