# RSAJWT

Simple use:
```c#
    //Password for public&private key file
    JWT.JWTUtils.RSAENCRYPTPASSORD = "Wsd345TgdskkE334";
    //public&private key file
    JWT.JWTUtils.RSAKEYPATH = "C:\\rsa1.txt";
    //public key in XML format, the library copy in rsapub1.PEM the same key in PEM format
    JWT.JWTUtils.RSAPUBKEYPATH = "C:\\rsapub1.xml";
    string t = JWT.JWTUtils.CreateToken("Alice", "2",JWT.Managers.SecretType.RSAKey);
    
    //token verification
    using StreamReader fileStream = new StreamReader("C:\\rsapub1.xml");
    string pubkey=fileStream.ReadToEnd();
    var v = JWT.JWTUtils.VerifyToken(t, k, JWT.Managers.SecretType.RSAKey);
    if (v.valid) {
        //use list of claims v.claims
    }        
                 
```