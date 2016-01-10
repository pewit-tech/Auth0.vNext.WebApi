using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.OptionsModel;
using Microsoft.AspNet.Authentication.JwtBearer;
using System.Security.Claims;
using System.IdentityModel.Tokens;
using Microsoft.AspNet.Authorization;

namespace Auth0.vNext.WebApi
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            // Set up configuration sources.
            var builder = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; set; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication();

            services.Configure<Auth0Settings>(Configuration.GetSection("Auth0"));

            // Add framework services.
            services.AddMvc();

            var defaultPolicy = new AuthorizationPolicyBuilder()
                    .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme‌​)
                    .RequireAuthenticatedUser().Build();

            // Enable the use of an [Authorize("Bearer")] attribute on methods and
            // classes to protect.
            services.AddAuthorization(auth =>
            {
                auth.AddPolicy("Bearer", defaultPolicy);
            });

            services.AddCors();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            var logger = loggerFactory.CreateLogger("Auth0");
            
            app.UseIISPlatformHandler(options => options.AuthenticationDescriptions.Clear());

            app.UseStaticFiles();

            app.UseCors(builder => builder.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod().AllowCredentials());
            
            var settings = app.ApplicationServices.GetService<IOptions<Auth0Settings>>();

            app.UseJwtBearerAuthentication(options =>
            {
                options.Audience = settings.Value.ClientId;
                options.Authority = $"https://{settings.Value.Domain}";
                options.AutomaticChallenge = true;
                options.AutomaticAuthenticate = true;
                // Automatically disable the HTTPS requirement for development scenarios.
                options.RequireHttpsMetadata = !env.IsDevelopment();
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    //HS256 not supported at lest in this version of vNext
                    //IssuerSigningKey = new SymmetricSecurityKey(Convert.FromBase64String(settings.Value.ClientSecret.Replace('-', '+').Replace('_', '/'))),
                    IssuerSigningKey = new X509SecurityKey(new System.Security.Cryptography.X509Certificates.X509Certificate2(Convert.FromBase64String(settings.Value.SigningCertificate))),
                    ValidAudience = settings.Value.ClientId,
                    ValidIssuer = options.Authority,
                    ValidateSignature = true,
                    ValidateLifetime = true,
                };
                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        logger.LogError("Authentication failed.", context.Exception);
                        return Task.FromResult(0);
                    },
                    OnValidatedToken = context =>
                    {
                        var claimsIdentity = context.AuthenticationTicket.Principal.Identity as ClaimsIdentity;
                        claimsIdentity.AddClaim(new Claim("id_token",
                            context.Request.Headers["Authorization"][0].Substring(context.AuthenticationTicket.AuthenticationScheme.Length + 1)));

                        foreach (var permission in context.AuthenticationTicket.Principal.FindAll("permissions"))
                        {
                            claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, permission.Value));
                        }

                        // OPTIONAL: you can read/modify the claims that are populated based on the JWT
                        // claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, claimsIdentity.FindFirst("name").Value));
                        return Task.FromResult(0);
                    },
                    OnChallenge = context =>
                    {
                        logger.LogInformation("OnChallenge.");
                        return Task.FromResult(0);
                    },
                    OnReceivedToken = context =>
                    {
                        logger.LogInformation("OnReceivedToken.");
                        return Task.FromResult(0);
                    },
                    OnReceivingToken = context =>
                    {
                        logger.LogInformation("OnReceivingToken.");
                        return Task.FromResult(0);
                    },
                };
            });

            //This line is important to be at the end for the authentication to work
            //otherwise the following exception would be thrown:
            //System.InvalidOperationException: No authentication handler is configured to authenticate for the scheme: Bearer
            app.UseMvc();
        }

        // Entry point for the application.
        public static void Main(string[] args) => WebApplication.Run<Startup>(args);
    }
}
