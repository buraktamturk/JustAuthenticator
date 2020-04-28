using JustAuthenticator.Models;
using JustAuthenticator.Token;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace JustAuthenticator.Tests
{
    public class TestServerTest : IDisposable
    {
        private readonly IHost host;
        private readonly TestServer testServer;
        private readonly HttpClient testClient;

        public TestServerTest()
        {
            this.host = new HostBuilder()
                .ConfigureWebHost(webBuilder =>
                {
                    webBuilder
                        .UseTestServer()
                        .UseStartup<MockStartup>();
                })
                .Start();

            this.testServer = this.host.GetTestServer();
            this.testClient = this.testServer.CreateClient();
        }

        public void Dispose()
        {
            this.testServer.Dispose();
        }

        [Fact]
        public async Task TestUserNamePasswordLogin()
        {
            using (var res = await this.testClient.PostAsync("/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "client_id", "test" },
                { "client_secret", "test" },
                { "grant_type", "password" },
                { "username", "test" },
                { "password", "test" }
            })))
            {
                res.EnsureSuccessStatusCode();

                var data = await Json<TokenResponse>(res);

                Assert.NotNull(data.access_token);
                Assert.NotNull(data.refresh_token);
                Assert.Equal("Bearer", data.token_type);
            }
        }

        [Fact]
        public async Task TestAuthorizedEndpointWithToken()
        {
            string accessToken;

            using (var res = await this.testClient.PostAsync("/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "client_id", "test" },
                { "client_secret", "test" },
                { "grant_type", "password" },
                { "username", "test" },
                { "password", "test" }
            })))
            {
                res.EnsureSuccessStatusCode();

                var data = await Json<TokenResponse>(res);

                Assert.NotNull(accessToken = data.access_token);
                Assert.NotNull(data.refresh_token);
                Assert.Equal("Bearer", data.token_type);
            }

            using (var res = await this.testClient.SendAsync(new HttpRequestMessage(HttpMethod.Get, "/authorized")
            {
                Headers =
                {
                    { "Authorization", $"Bearer {accessToken}" }
                }
            }))
            {
                res.EnsureSuccessStatusCode();

                var data = await res.Content.ReadAsStringAsync();

                Assert.Equal("hello world 2", data);
            }
        }

        [Fact]
        public async Task TestAuthorizedEndpointWithoutToken()
        {
            using (var res = await this.testClient.GetAsync("/authorized"))
            {
                Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
            }
        }

        [Fact]
        public async Task TestNotAuthorizedEndpoint()
        {
            using (var res = await this.testClient.GetAsync("/"))
            {
                res.EnsureSuccessStatusCode();

                var data = await res.Content.ReadAsStringAsync();

                Assert.Equal("hello world", data);
            }
        }

        [Fact]
        public async Task TestUserNamePasswordLoginInvalid()
        {
            using (var res = await this.testClient.PostAsync("/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "client_id", "test" },
                { "client_secret", "test" },
                { "grant_type", "password" },
                { "username", "test" },
                { "password", "test1" }
            })))
            {
                Assert.Equal(401, (int)res.StatusCode);

                var data = await Json<OAuth2ErrorResponse>(res);
                Assert.Equal("invalid_grant", data.code);
            }
        }

        [Fact]
        public async Task TestInvalidClient()
        {
            using (var res = await this.testClient.PostAsync("/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "client_id", "test" },
                { "client_secret", "123" },
                { "grant_type", "password" },
                { "username", "test" },
                { "password", "test" }
            })))
            {
                Assert.Equal(401, (int)res.StatusCode);

                var data = await Json<OAuth2ErrorResponse>(res);
                Assert.Equal("invalid_client", data.code); 
            }
        }

        [Fact]
        public async Task TestRefreshToken()
        {
            string refreshToken;
            using (var res = await this.testClient.PostAsync("/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "client_id", "test" },
                { "client_secret", "test" },
                { "grant_type", "password" },
                { "username", "test" },
                { "password", "test" }
            })))
            {
                res.EnsureSuccessStatusCode();

                var data = await Json<TokenResponse>(res);

                Assert.NotNull(data.access_token);
                Assert.NotNull(data.refresh_token);
                Assert.Equal("Bearer", data.token_type);

                refreshToken = data.refresh_token;
            }

            using (var res = await this.testClient.PostAsync("/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "client_id", "test" },
                { "client_secret", "test" },
                { "grant_type", "refresh_token" },
                { "refresh_token", refreshToken }
            })))
            {
                res.EnsureSuccessStatusCode();

                var data = await Json<TokenResponse>(res);

                Assert.NotNull(data.access_token);
                Assert.NotNull(data.refresh_token);
                Assert.Equal("Bearer", data.token_type);

                refreshToken = data.refresh_token;
            }
        }

        private async Task<T> Json<T>(HttpResponseMessage msg)
        {
            return JsonConvert.DeserializeObject<T>(await msg.Content.ReadAsStringAsync());
        }

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

        public class MockAuthenticationService : IAuthenticatorService<TestClient, TestUser>
        {
            IPasswordProvider passwordProvider;
            MockAuthenticationData authenticationData;

            public MockAuthenticationService(IPasswordProvider passwordProvider, MockAuthenticationData authenticationData)
            {
                this.passwordProvider = passwordProvider;
                this.authenticationData = authenticationData;
            }

            public async Task<TestClient> GetClient(string client_id, IPassword client_secret)
            {
                var client = authenticationData.clients.FirstOrDefault(a => a.id == client_id);
                if (client == null)
                    return null;

                if (!client_secret.Compare(passwordProvider.Generate(client.password).Hashed))
                    return null;

                return client;
            }

            public async Task<TestUser> GetUser(TestClient client, string username, IPassword password, bool trusted)
            {
                var user = authenticationData.users.FirstOrDefault(a => a.email == username);
                if (user == null)
                    return null;

                if (!password.Compare(passwordProvider.Generate(user.password).Hashed))
                    return null;

                return user;
            }

            public async Task<ClaimsIdentity> MakeClaims(TestClient client, TestUser user)
            {
                var claims = new ClaimsIdentity();



                return claims;
            }

            public async Task SaveToken(TestClient client, TestUser user, ICode token, bool disposable)
            {
                authenticationData.tokens[token.id] = (user, token.password.Hashed, disposable);
            }

            public async Task<TestUser> ValidateToken(TestClient client, ICode token, bool dispose)
            {
                if(!authenticationData.tokens.TryGetValue(token.id, out var data) || data.disposable != dispose || !token.password.Compare(data.token))
                {
                    return null;
                }

                return data.user;
            }
        }

        public class MockStartup
        {
            // This method gets called by the runtime. Use this method to add services to the container.
            // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
            public void ConfigureServices(IServiceCollection services)
            {
                services
                    .AddSingleton<MockAuthenticationData>()
                    .AddRouting()
                    .AddMvcCore();

                services
                    .AddAuthorization()
                    .AddJustAuthenticator(builder => builder
                        .UseSymmetricKey("Test12341234jhkhkjhkjhkj")
                        .UseHandler<MockAuthenticationService, TestClient, TestUser>()
                        .SetIssuer("Test")
                        .SetAudience("Test Users")
                        .SetExpiration(TimeSpan.FromHours(1))
                        .Build());
            }

            // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
            public void Configure(IApplicationBuilder app)
            {
                app.UseRouting();

                app.UseAuthentication()
                    .UseAuthorization();

                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapJustAuthenticator("/oauth2/token");

                    endpoints.MapControllers();
                });
            }
        }

        public class MockProgram { 
            public static IHostBuilder CreateHostBuilder(string[] args) =>
                Host.CreateDefaultBuilder(args)
                    .ConfigureWebHostDefaults(webBuilder =>
                    {
                        webBuilder.UseStartup<MockStartup>();
                    });
        }
    }

    public class DefaultController : ControllerBase
    {
        [HttpGet("/")]
        public string test()
        {
            return "hello world";
        }

        [Authorize]
        [HttpGet("/authorized")]
        public string testAuthorized()
        {
            return "hello world 2";
        }
    }
}
