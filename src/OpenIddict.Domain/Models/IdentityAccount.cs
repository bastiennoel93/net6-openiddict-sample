using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace OpenIddict.Domain.Models;


public class IdentityAccount : IdentityUser
{
    public User User { get; set; }
}