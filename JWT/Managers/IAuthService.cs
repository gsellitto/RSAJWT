using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using JWT.Models;

namespace JWT.Managers
{
    public enum SecretType
    {
        Password = 1,
        RSAKey = 2
    }

    interface IAuthService
    {
        string SecretKey { get; set; }
        SecretType Type { get; set; }

        bool IsTokenValid(string token);
        string GenerateToken(IAuthContainerModel model);
        IEnumerable<Claim> GetTokenClaims(string token);
        
    }
}
