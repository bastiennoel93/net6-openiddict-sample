using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Domain.Models;
using OpenIddict.Store;
using OpenIddict.Validation.AspNetCore;

namespace OpenIddict.Api.Configurations;

public static class Authentication
{
    public static IServiceCollection AddAuthentication(this IServiceCollection services, IConfiguration configuration, IWebHostEnvironment environment)
    {
        services.AddIdentity<IdentityAccount, IdentityRole>(o =>
            {
                o.Password.RequireDigit = false;
                o.Password.RequireLowercase = false;
                o.Password.RequireUppercase = false;
                o.Password.RequireNonAlphanumeric = false;
                o.Password.RequiredLength = 5;
            })
            .AddSignInManager()
            .AddEntityFrameworkStores<OpenIddictContext>()
            .AddDefaultTokenProviders();

        services.AddOpenIddict()
            .AddCore(options => options.UseEntityFrameworkCore().UseDbContext<OpenIddictContext>())
            .AddServer(options =>
            {
                options.UseDataProtection();

                options.SetAuthorizationEndpointUris("/connect/authorize")
                    .SetTokenEndpointUris("/connect/token")
                    .SetIntrospectionEndpointUris("/connect/introspect");

                options.AllowPasswordFlow();
                options.AllowRefreshTokenFlow();

                options.UseReferenceAccessTokens();
                options.UseReferenceRefreshTokens();

                options.RegisterScopes(OpenIddictConstants.Permissions.Scopes.Email,
                    OpenIddictConstants.Permissions.Scopes.Profile,
                    OpenIddictConstants.Permissions.Scopes.Roles);

                options.SetAccessTokenLifetime(TimeSpan.FromHours(12));
                options.SetRefreshTokenLifetime(TimeSpan.FromDays(7));

                options.AddEncryptionKey(new SymmetricSecurityKey(Convert.FromBase64String(configuration["Jwt:Key"])));

                if (environment.IsProduction())
                {
                    //TODO add a prod certificate!
                    //https://documentation.openiddict.com/configuration/encryption-and-signing-credentials.html
                }
                else
                {
                    options.AddDevelopmentEncryptionCertificate()
                        .AddDevelopmentSigningCertificate();
                }

                //options.DisableAccessTokenEncryption();

                options.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableTokenEndpointPassthrough();
            })
            .AddValidation(options =>
            {
                options.AddEncryptionKey(new SymmetricSecurityKey(Convert.FromBase64String(configuration["Jwt:Key"])));
                if (environment.IsProduction())
                {
                    options.SetIssuer(configuration["Jwt:Issuer"]);
                    options.AddAudiences("Jwt:Audience");
                    options.UseSystemNetHttp();
                }
                else
                {
                    options.UseLocalServer();
                }

                options.UseDataProtection();
                options.UseAspNetCore();
            });

        services.AddAuthentication(options =>
        {
            options.DefaultScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
            options.DefaultAuthenticateScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
        });
        services.AddAuthorization();

        return services;
    }
}