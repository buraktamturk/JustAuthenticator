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

        [Fact]
        public async Task TestNonExistentRefreshToken()
        {
            var token = this.testServer.Services.CreateScope().ServiceProvider
                .GetRequiredService<ICodeProvider>()
                .New();

            using (var res = await this.testClient.PostAsync("/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "client_id", "test" },
                { "client_secret", "test" },
                { "grant_type", "refresh_token" },
                { "refresh_token", token.code }
            })))
            {
                Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);

                var data = await Json<OAuth2ErrorResponse>(res);
                Assert.Equal("invalid_grant", data.code);
            }
        }

        [Fact]
        public async Task TestNonExistentExchangeCode()
        {
            var token = this.testServer.Services.CreateScope().ServiceProvider
                .GetRequiredService<ICodeProvider>()
                .New("test");

            using (var res = await this.testClient.PostAsync("/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "client_id", "test" },
                { "client_secret", "test" },
                { "grant_type", "authorization_code" },
                { "code", token.code },
                { "redirect_uri", "test" }
            })))
            {
                Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);

                var data = await Json<OAuth2ErrorResponse>(res);
                Assert.Equal("invalid_grant", data.code);
            }
        }

        [Fact]
        public async Task TestExistingExchangeCode()
        {
            var token = this.testServer.Services.CreateScope().ServiceProvider
                .GetRequiredService<ICodeProvider>()
                .New("http://test");

            await this.testServer.Services.CreateScope().ServiceProvider
                .GetRequiredService<IAuthenticatorService<TestClient, TestUser>>()
                .SaveToken(new TestClient { }, new TestUser { }, token, true);

            using (var res = await this.testClient.PostAsync("/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "client_id", "test" },
                { "client_secret", "test" },
                { "grant_type", "authorization_code" },
                { "code", token.code },
                { "redirect_uri", "http://test" }
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
        public async Task TestExistingExchangeCodeAsRefreshToken()
        {
            var token = this.testServer.Services.CreateScope().ServiceProvider
                .GetRequiredService<ICodeProvider>()
                .New();

            await this.testServer.Services.CreateScope().ServiceProvider
                .GetRequiredService<IAuthenticatorService<TestClient, TestUser>>()
                .SaveToken(new TestClient { }, new TestUser { }, token, true);

            using (var res = await this.testClient.PostAsync("/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "client_id", "test" },
                { "client_secret", "test" },
                { "grant_type", "refresh_token" },
                { "refresh_token", token.code }
            })))
            {
                Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
            }
        }

        private object IAuthenticatorService<T1, T2>()
        {
            throw new NotImplementedException();
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

            public Task<TestClient> GetClient(string client_id, IPassword client_secret)
            {
                var client = authenticationData.clients.FirstOrDefault(a => a.id == client_id);
                if (client == null)
                    return Task.FromResult<TestClient>(null);

                if (!client_secret.Compare(passwordProvider.Generate(client.password).Hashed))
                    return Task.FromResult<TestClient>(null);

                return Task.FromResult(client);
            }

            public Task<TestUser> GetUser(TestClient client, string username, IPassword password, bool trusted)
            {
                var user = authenticationData.users.FirstOrDefault(a => a.email == username);
                if (user == null)
                    return Task.FromResult<TestUser>(null);

                if (!password.Compare(passwordProvider.Generate(user.password).Hashed))
                    return Task.FromResult<TestUser>(null);

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
                    return Task.FromResult<TestUser>(null);
                }

                return Task.FromResult(data.user);
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
