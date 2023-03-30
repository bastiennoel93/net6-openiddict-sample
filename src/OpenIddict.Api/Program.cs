using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using OpenIddict.Abstractions;
using OpenIddict.Api.Configurations;
using OpenIddict.Domain.Models;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Store;
using OpenIddict.Validation.AspNetCore;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddAuthentication(builder.Configuration, builder.Environment);

builder.Services
    .AddDbContext<OpenIddictContext>(options =>
    {
        options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"));
        options.UseOpenIddict();
    });

builder.Services.AddAuthentication(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
builder.Services.AddAuthorization();

var app = builder.Build();

var logger = app.Services.GetRequiredService<ILogger<Program>>();
logger.LogDebug("Host created.");

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();

await using (var scope = app.Services.CreateAsyncScope())
{
    var context = scope.ServiceProvider.GetRequiredService<OpenIddictContext>();
    await context.Database.EnsureCreatedAsync();

    await StoreInitializer.Init(scope);
}

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/authorize", [Authorize]
(ClaimsPrincipal user) => user.Identity!.Name);

app.MapPost("/connect/token", async (HttpContext context,
    IOpenIddictApplicationManager manager,
    UserManager<IdentityAccount> userManager,
    SignInManager<IdentityAccount> signInManager,
    IConfiguration configuration
    ) =>
{
    var request = context.GetOpenIddictServerRequest();

    var credentialError = new AuthenticationProperties(new Dictionary<string, string?>
    {
        [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidGrant,
        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The credentials is invalid."
    });

    if (request == null)
    {
        return Results.Forbid(credentialError);
    }

    if (request.IsAuthorizationCodeGrantType())
    {
        return Results.Forbid(new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidGrant,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The specified grant is not implemented."
        }));
    }

    if (request.IsRefreshTokenGrantType())
    {
        var claimsPrincipal = (await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;
        if (claimsPrincipal == null)
            return Results.Unauthorized();

        return Results.SignIn(claimsPrincipal, properties: null,
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    var invalidClientError = new AuthenticationProperties(new Dictionary<string, string?>
    {
        [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidClient,
        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The ClientId is invalid."
    });

    if (string.IsNullOrEmpty(request.ClientId) || string.IsNullOrEmpty(request.ClientSecret))
    {
        return Results.Forbid(invalidClientError);
    }

    var application = await manager.FindByClientIdAsync(request.ClientId, context.RequestAborted);

    if (application == null)
    {
        return Results.Forbid(invalidClientError);
    }

    var clientIsValid = await manager.ValidateClientSecretAsync(application, request.ClientSecret, context.RequestAborted);

    if (!clientIsValid)
    {
        return Results.Forbid(invalidClientError);
    }

    var identityAccount = await userManager.FindByNameAsync(request.Username);

    if (identityAccount == null)
    {
        return Results.Forbid(credentialError);
    }
    var passwordValidResult = await signInManager.CheckPasswordSignInAsync(identityAccount, request.Password, lockoutOnFailure: false);
    if (!passwordValidResult.Succeeded)
    {
        return Results.Forbid(credentialError);
    }

    var user = await userManager.Users.Select(x => x.User).FirstOrDefaultAsync(x => x.UserName == identityAccount.UserName);
    if (user != null)
    {
        var userRoles = await userManager.GetRolesAsync(identityAccount);

        var jwtSub = configuration["Jwt:Subject"] + " " + user.Id;
        var issuer = configuration["Jwt:Issuer"];
        var audience = configuration["Jwt:Audience"];

        var claims = new List<Claim>()
        {
            new(JwtRegisteredClaimNames.Sub, jwtSub, issuer),
            new(ClaimTypes.Name, identityAccount.UserName, issuer),
            new(ClaimTypes.NameIdentifier, user.Id.ToString(), issuer),
            new(ClaimTypes.Email, identityAccount.Email),
            new(ClaimTypes.GivenName, user.FirstName),
            new("family_name", user.LastName),
            new(OpenIddictConstants.Claims.Subject, user.Id.ToString()),
            new(OpenIddictConstants.Claims.Username, identityAccount.UserName)
        };

        claims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

        var identity = new ClaimsIdentity(claims,
            OpenIddictConstants.Schemes.Bearer,
            ClaimTypes.Name,
            ClaimTypes.Role);

        identity.AddClaim(OpenIddictConstants.Claims.Name, identityAccount.UserName,
            OpenIddictConstants.Destinations.AccessToken);
        identity.AddClaim(OpenIddictConstants.Claims.Subject, jwtSub, OpenIddictConstants.Destinations.AccessToken);
        identity.AddClaim(OpenIddictConstants.Claims.Audience, audience, OpenIddictConstants.Destinations.AccessToken);

        var claimsPrincipal = new ClaimsPrincipal(identity);

        claimsPrincipal.SetDestinations(static claim => claim.Type switch
        {
            ClaimTypes.Name when claim.Subject.HasScope(OpenIddictConstants.Permissions.Scopes.Profile) => new[]
            {
                OpenIddictConstants.Destinations.AccessToken,
                OpenIddictConstants.Destinations.IdentityToken
            },
            _ => new[]
            {
                OpenIddictConstants.Destinations.AccessToken
            }
        });
        var scopes = new[]
        {
            OpenIddictConstants.Scopes.OpenId,
            OpenIddictConstants.Scopes.Email,
            OpenIddictConstants.Scopes.Profile,
            OpenIddictConstants.Scopes.OfflineAccess,
            OpenIddictConstants.Scopes.Roles
        };
        claimsPrincipal.SetScopes(scopes);

        return Results.SignIn(new ClaimsPrincipal(identity), properties: null,
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    return Results.Unauthorized();
});

app.Run();
logger.LogDebug("Application started.");