using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JWT.Models
{
    class JWTContainerModel : IAuthContainerModel
    {
        public string Issuer { get; set; } = "EPC";

        public string SecretKey { get; set; }

        public Managers.SecretType Type { get; set; } = Managers.SecretType.Password;

        public string SecurityAlgorithm { get ; set ; }= SecurityAlgorithms.HmacSha256Signature;

        public int ExpireMinutes { get; set; } = 10080;
        public Claim[] Claims { get ; set ; }

        

    }
}
