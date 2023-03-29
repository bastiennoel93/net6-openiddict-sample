using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.Domain.Models;
using System.Data;

namespace OpenIddict.Store;

public static class StoreInitializer
{
    public static async Task Init(AsyncServiceScope scope)
    {
        await CreateApplicationsAsync(scope);
        await CreateScopesAsync(scope);
        await SetDefaultUsersAndRoles(scope);
    }

    private static async Task CreateApplicationsAsync(AsyncServiceScope scope)
    {
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            if (await manager.FindByClientIdAsync("console_app") is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "console_app",
                    ClientSecret = "secret",
                    Permissions =
                    {
                        OpenIddictConstants.Permissions.Endpoints.Authorization,
                        OpenIddictConstants.Permissions.Endpoints.Token,
                        OpenIddictConstants.Permissions.GrantTypes.Password,
                        OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                        OpenIddictConstants.Permissions.ResponseTypes.Code,
                        OpenIddictConstants.Permissions.Scopes.Email,
                        OpenIddictConstants.Permissions.Scopes.Profile,
                        OpenIddictConstants.Permissions.Scopes.Roles,
                        OpenIddictConstants.Permissions.Prefixes.Scope + "api1"
                    }
                });
            }

            if (await manager.FindByClientIdAsync("resource_server") is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "resource_server",
                    ClientSecret = "secret",
                    Permissions =
                    {
                        OpenIddictConstants.Permissions.Endpoints.Introspection
                    }
                });
            }
    }


    public static async Task CreateScopesAsync(AsyncServiceScope scope)
    {
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

        if (await manager.FindByNameAsync("api1") is null)
        {
            await manager.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "api1",
                Resources =
                {
                    "console_app",
                    "resource_server"
                }
            });
        }
    }

    private static async Task SetDefaultUsersAndRoles(AsyncServiceScope scope)
    {
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityAccount>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        var defaultAdmin = new User
        {
            UserName = "0000",
            FirstName = "John",
            LastName = "Doe",
            Email = "test@test.com",
            PhoneNumber = "0000000000"
        };

        var account = new IdentityAccount
        {
            User = defaultAdmin,
            UserName = defaultAdmin.UserName,
            Email = defaultAdmin.Email,
            EmailConfirmed = false,
            PhoneNumber = defaultAdmin.PhoneNumber,
        };

        if (!await roleManager.RoleExistsAsync("admin"))
        {
            await roleManager.CreateAsync(new IdentityRole("admin"));
        }
        
        if (!userManager.Users.Any(x => x.UserName == defaultAdmin.UserName))
        {
            await userManager.CreateAsync(account, "password");

            await userManager.AddToRolesAsync(account, new List<string>{ "admin" });
        }
    }
}