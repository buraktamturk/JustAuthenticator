using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace JustAuthenticator.SampleWeb
{
    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services
                .AddAuthorization()
                .AddJustAuthenticator(builder => builder
                    .UseSymmetricKey("Test12341234jhkhkjhkjhkj")
                    .UseHandler<UserAuthenticationService, TestClient, TestUser>()
                    .SetIssuer("Test")
                    .SetAudience("Test Users")
                    .SetExpiration(TimeSpan.FromHours(1))
                    .Build());
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();
            app.UseAuthentication()
                .UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapJustAuthenticator();

                endpoints.MapGet("/", async context =>
                {
                    await context.Response.WriteAsync("Hello World!");
                });
            });
        }
    }
}
