using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Domain.Models;

namespace OpenIddict.Store;

public class OpenIddictContext : IdentityDbContext<IdentityAccount>
{
    public OpenIddictContext(DbContextOptions<OpenIddictContext> options) : base(options)
    {
    }

    public DbSet<User> Users { get; set; }
}