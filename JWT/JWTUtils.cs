using JWT.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;


namespace JWT
{
    public class JWTUtils
    {
        public static string PASSORD { get; set; } = string.Empty;
        public static string RSAKEYPATH { get; set; } = string.Empty;
        public static string RSAPUBKEYPATH { get; set; } = string.Empty;
        public static string RSAENCRYPTPASSORD { get; set; } = string.Empty;

        public static (bool valid, List<Claim> claims) VerifyToken(string token,string secretKey, Managers.SecretType secretType )
        {
            Managers.IAuthService authService = new Managers.JWTService(secretKey, secretType);
            bool valid = authService.IsTokenValid(token);
            if (valid)
            {
                return (true, authService.GetTokenClaims(token).ToList());
            }
            return (false, null);
        }

        public static string CreateToken(string user, string codutente, Managers.SecretType secretType)
        {

            IAuthContainerModel model;
            if (secretType == Managers.SecretType.RSAKey)
            {
                model = GetJWTContainerModelRsa(user, codutente);
            }
            else
            {
                model = GetJWTContainerModelPassword(user, codutente);
            }
            System.Diagnostics.Debug.Write($"Password { model.SecretKey} _{user}_{codutente}_");
            Managers.IAuthService authService = new Managers.JWTService(model.SecretKey, secretType);
            return authService.GenerateToken(model);
        }

        private static JWTContainerModel GetJWTContainerModelPassword(string name, string codutente)
        {
            return new JWTContainerModel
            {
                Claims = new Claim[] {
                new Claim(ClaimTypes.Name ,name ),
                new Claim(ClaimTypes.Sid  ,codutente)
            }, SecretKey= Password()
            };
        }

        
        public static string Password()
        {
            if (string.IsNullOrEmpty(PASSORD))
                throw new ArgumentException("PASSORD not set ");
            return PASSORD;
        }

        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        
        private static (string rsaKeyPath, string rsaPubKeyPath,string encrypPassword) GetPath()
        {

            if (string.IsNullOrEmpty( RSAKEYPATH))
                throw new ArgumentException("RSAKEYPATH not set ");
            if (string.IsNullOrEmpty(RSAPUBKEYPATH ))
                throw new ArgumentException("RSAPUBKEYPATH not set ");
            if (string.IsNullOrEmpty(RSAENCRYPTPASSORD))
                throw new ArgumentException("RSAENCRYPTPASSORD not set ");

            return (RSAKEYPATH ,RSAPUBKEYPATH, RSAENCRYPTPASSORD);                     
        }

        private static JWTContainerModel GetJWTContainerModelRsa(string name, string codutente)
        {
            var p = GetPath();
            var rsaProvider = new RSAKeyProvider(p.rsaKeyPath ,p.rsaPubKeyPath );
            string rsaPrivatePublicKeyXML = rsaProvider.GetPrivateAndPublicKey(p.encrypPassword );
            return new JWTContainerModel
            {
                Claims = new Claim[] {
                new Claim(ClaimTypes.Name ,name ),
                new Claim(ClaimTypes.Sid,codutente)
            },
                SecretKey = rsaPrivatePublicKeyXML,
                Type=Managers.SecretType.RSAKey    ,
                SecurityAlgorithm= SecurityAlgorithms.RsaSha256
            };
        }
    }
}
