using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Antiforgery;
using AspNetCore.Antiforgery.Aes;

namespace Example
{
    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();

            var key = Convert.FromBase64String("PoQ2zO0w8A/n8eXl3eoN2AQXYhSIyMXJW2QVTzJOVA4=");
            var iv = Convert.FromBase64String("L3RrIxqIug+XVp9/fiV4AQ==");

            services.AddScoped<IAntiforgery, AesAntiforgery>(p =>
                 new AesAntiforgery(p.GetService<ILogger<AesAntiforgery>>(), key, iv, TimeSpan.FromHours(12)));
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(LogLevel.Debug);

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseMvcWithDefaultRoute();
        }
    }
}
