using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JWT.Models
{
    interface IAuthContainerModel
    {
        string Issuer { get; set; }

        string SecretKey { get; set; }
        Managers.SecretType Type { get; set; }

        string SecurityAlgorithm { get; set; }
        int ExpireMinutes { get; set; }
        Claim[] Claims { get; set; }
    }
}
