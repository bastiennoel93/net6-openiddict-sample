using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Domain.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace OpenIddict.Store;

public class OpenIddictContext : IdentityDbContext<IdentityAccount>
{

    public OpenIddictContext(DbContextOptions<OpenIddictContext> options) : base(options)
    {

    }

    public DbSet<User> Users { get; set; }
}