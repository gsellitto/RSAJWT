using System;
using System.IO;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Diagnostics;

namespace JWT
{

    public class RSAKeyProvider
    {

        string rsaKeyPath { get; set; }
        string rsaPubKeyPath { get; set; }


        public RSAKeyProvider(string rsaKeyPath, string rsaPubKeyPath)

        {
            this.rsaKeyPath = rsaKeyPath;
            this.rsaPubKeyPath = rsaPubKeyPath;
        }

        public string GetPrivateAndPublicKey(string encryptKey)
        {
            string result = ReadPrivateAndPublicKey(encryptKey);
            if (string.IsNullOrEmpty(result))
            {
                var key = CreatePrivateAndPublicKey();
                Boolean isInserted = InsertPrivateAndPublicKey(key, encryptKey);
                if (isInserted)
                    result = key;
            }
            return result;
        }

        /// <summary>
        /// Crea la chiave pubblica e provata RSA in formato XML
        /// </summary>
        private string CreatePrivateAndPublicKey()
        {
            using RSACryptoServiceProvider myRSA = new RSACryptoServiceProvider(4096);
            //RSAParameters publicKey = myRSA.ExportParameters(true);
            string publicAndPrivateKey = myRSA.ToXmlString(true);
            return publicAndPrivateKey;
        }

        /// <summary>
        /// Salva la chiave privata e pubblica in un file XML cifrato con blowfish, poi salva la chiave pubblica in formato
        /// XML e in formato PEM
        /// </summary>
        /// <param name="key">RSA key da esportare</param>
        /// <param name="encryptKey">Chiave BlowFish con cui cifrare il file</param>
        /// <returns></returns>
        private Boolean InsertPrivateAndPublicKey(string key, string encryptKey)
        {
            Boolean result = false;
            try
            {
                using (StreamWriter fileStream = new StreamWriter(rsaKeyPath))
                {
                    fileStream.WriteLine(EncryptString(key,encryptKey ));
                    fileStream.Flush();
                    result = true;
                }
                using RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString(key);
                using (StreamWriter fileStream = new StreamWriter(rsaPubKeyPath))
                {
                    fileStream.WriteLine(rsa.ToXmlString(false));
                    fileStream.Flush();
                    result = true;
                }                
                string f = Path.Combine(Path.GetDirectoryName(rsaPubKeyPath), Path.GetFileNameWithoutExtension(rsaPubKeyPath) + ".PEM");
                using (StreamWriter fileStream = new StreamWriter(f))
                {
                    ExportPublicKey(rsa, fileStream);
                    result = true;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
                result = false;
            }
            return result;
        }

        /// <summary>
        /// Decifra con BlowFish
        /// </summary>
        /// <param name="Text"></param>
        /// <param name="Key"></param>
        /// <returns></returns>
        private string DecryptString(string Text, string Key)
        {
            BlowFishCS.BlowFish crypt = new BlowFishCS.BlowFish(Key);
            return crypt.Decrypt_CBC(Text);
        }

        /// <summary>
        /// Cifra con BlowFish
        /// </summary>
        /// <param name="Text"></param>
        /// <param name="Key"></param>
        /// <returns></returns>
        private string EncryptString(string Text, string Key)
        {
            BlowFishCS.BlowFish crypt = new BlowFishCS.BlowFish(Key);
            return crypt.Encrypt_CBC(Text);
        }

        private string ReadPrivateAndPublicKey(string encryptKey)
        {
            String result = null;
            try
            {
                using (StreamReader fileStream = new StreamReader(rsaKeyPath))
                {
                    result = DecryptString(fileStream.ReadToEnd(),encryptKey);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
            }
            return result;
        }

        private static void ExportPublicKey(RSACryptoServiceProvider csp, TextWriter outputStream)
        {
            var parameters = csp.ExportParameters(false);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    innerWriter.Write((byte)0x30); // SEQUENCE
                    EncodeLength(innerWriter, 13);
                    innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
                    var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                    EncodeLength(innerWriter, rsaEncryptionOid.Length);
                    innerWriter.Write(rsaEncryptionOid);
                    innerWriter.Write((byte)0x05); // NULL
                    EncodeLength(innerWriter, 0);
                    innerWriter.Write((byte)0x03); // BIT STRING
                    using (var bitStringStream = new MemoryStream())
                    {
                        var bitStringWriter = new BinaryWriter(bitStringStream);
                        bitStringWriter.Write((byte)0x00); // # of unused bits
                        bitStringWriter.Write((byte)0x30); // SEQUENCE
                        using (var paramsStream = new MemoryStream())
                        {
                            var paramsWriter = new BinaryWriter(paramsStream);
                            EncodeIntegerBigEndian(paramsWriter, parameters.Modulus); // Modulus
                            EncodeIntegerBigEndian(paramsWriter, parameters.Exponent); // Exponent
                            var paramsLength = (int)paramsStream.Length;
                            EncodeLength(bitStringWriter, paramsLength);
                            bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                        }
                        var bitStringLength = (int)bitStringStream.Length;
                        EncodeLength(innerWriter, bitStringLength);
                        innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                    }
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                outputStream.WriteLine("-----BEGIN PUBLIC KEY-----");
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                }
                outputStream.WriteLine("-----END PUBLIC KEY-----");
            }
        }

        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }
        
            }
}
