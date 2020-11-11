using JustAuthenticator.Token;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace JustAuthenticator.SampleWeb
{
    public class TestClient
    {
        public string id { get; set; }

        public string password { get; set; }
    }

    public class TestUser
    {
        public string email { get; set; }

        public string password { get; set; }
    }

    public class MockAuthenticationData
    {
        public List<TestClient> clients = new List<TestClient>()
            {
                new TestClient()
                {
                    id = "test",
                    password = "test"
                }
            };

        public List<TestUser> users = new List<TestUser>()
            {
                new TestUser()
                {
                    email = "test",
                    password = "test"
                }
            };

        public Dictionary<Guid, (TestUser user, string token, bool disposable)> tokens
            = new Dictionary<Guid, (TestUser user, string token, bool disposable)>();
    }

    public class UserAuthenticationService : IAuthenticatorService<TestClient, TestUser>
    {
        private readonly IPasswordProvider passwordProvider;
        private readonly MockAuthenticationData authenticationData;

        public UserAuthenticationService(IPasswordProvider passwordProvider, MockAuthenticationData authenticationData)
        {
            this.passwordProvider = passwordProvider;
            this.authenticationData = authenticationData;
        }

        public Task<TestClient> GetClient(string client_id, IPassword client_secret)
        {
            var client = authenticationData.clients.FirstOrDefault(a => a.id == client_id);
            if (client == null)
                return null;

            if (!client_secret.Compare(passwordProvider.Generate(client.password).Hashed))
                return null;

            return Task.FromResult(client);
        }

        public Task<TestUser> GetUser(TestClient client, string username, IPassword password, bool trusted)
        {
            var user = authenticationData.users.FirstOrDefault(a => a.email == username);
            if (user == null)
                return null;

            if (!password.Compare(passwordProvider.Generate(user.password).Hashed))
                return null;

            return Task.FromResult(user);
        }

        public Task<ClaimsIdentity> MakeClaims(TestClient client, TestUser user)
        {
            var claims = new ClaimsIdentity();



            return Task.FromResult(claims);
        }

        public Task SaveToken(TestClient client, TestUser user, ICode token, bool disposable)
        {
            authenticationData.tokens[token.id] = (user, token.password.Hashed, disposable);
            return Task.CompletedTask;
        }

        public Task<TestUser> ValidateToken(TestClient client, ICode token, bool dispose)
        {
            if (!authenticationData.tokens.TryGetValue(token.id, out var data) || data.token == null || data.disposable != dispose || !token.password.Compare(data.token))
            {
                return null;
            }

            return Task.FromResult(data.user);
        }
    }
}
