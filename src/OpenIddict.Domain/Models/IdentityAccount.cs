using Microsoft.AspNetCore.Identity;

namespace OpenIddict.Domain.Models;

public class IdentityAccount : IdentityUser
{
    public User User { get; set; }
}