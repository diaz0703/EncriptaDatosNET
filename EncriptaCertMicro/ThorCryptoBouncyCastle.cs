using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;
using System.Text;
using Org.BouncyCastle.X509;


namespace EncriptaCertMicro
{
    public class ThorCryptoBouncyCastle
    {
        public static string certificateNamePrivate = "C:\\DiscoD\\Temp\\xml\\star_thorsolpruebas__pd_crt_pass.pem";
        public static string certificateNamePublic = "C:\\DiscoD\\Temp\\xml\\star_thorsolpruebas.crt";
        public static string sSecret = "*123456*";


        public void Proceso()
        {
            string sTextoAEncriptar = "El texto que se encriptará";
            string sEncryptedSecret = string.Empty;
            string sDecryptedSecret = string.Empty;

            // Encryption Publica
            Console.WriteLine("Original:   {0}", sTextoAEncriptar);
            Console.WriteLine("-------------------AAAAAAAAAAAAAAAAAAA--------------------");
            sEncryptedSecret = RsaEncryptWithPublic(sTextoAEncriptar, certificateNamePublic);
            Console.WriteLine("Encriptado público:   {0}", sEncryptedSecret);

            Console.WriteLine("-------------------AAAAAAAAAAAAAAAAAAA--------------------");
            // Decryption Privada
            sDecryptedSecret = RsaDecryptPrivada(sEncryptedSecret, certificateNamePrivate);
            Console.WriteLine("Desencriptado privado: {0}", sDecryptedSecret);
            Console.WriteLine("-------------------AAAAAAAAAAAAAAAAAAA--------------------");


            sTextoAEncriptar = "El texto que se encriptará de regreso";
            // Encryption Privada
            Console.WriteLine("Original:   {0}", sTextoAEncriptar);
            Console.WriteLine("-------------------AAAAAAAAAAAAAAAAAAA--------------------");
            sEncryptedSecret = RsaEncryptWithPrivate(sTextoAEncriptar, certificateNamePrivate);
            Console.WriteLine("Encriptado privado:   {0}", sEncryptedSecret);
            Console.WriteLine("-------------------AAAAAAAAAAAAAAAAAAA--------------------");

            // Decryption Publica
            sDecryptedSecret = RsaDecryptPublica(sEncryptedSecret, certificateNamePublic);
            Console.WriteLine("Desencriptado público: {0}", sDecryptedSecret);
            Console.WriteLine("-------------------AAAAAAAAAAAAAAAAAAA--------------------");


            ////Display the original data and the decrypted data.
            Console.WriteLine("Termina el proceso.");
        }


        public string RsaDecryptPrivada(string base64Input
                               , string privateKey)
        {
            var bytesToDecrypt = Convert.FromBase64String(base64Input);
            var decryptEngine = new Pkcs1Encoding(new RsaEngine());
            using (var txtreader = new StringReader(File.ReadAllText(privateKey)))
            {
                var pemReader = new PemReader(txtreader, new PasswordFinder(sSecret));
                var pemObject = pemReader.ReadObject();
                AsymmetricKeyParameter _privateKey = (AsymmetricKeyParameter)pemObject;
                decryptEngine.Init(false, _privateKey);
            }
            var decrypted = Encoding.UTF8.GetString(decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length));
            return decrypted;
        }
        public string RsaDecryptPublica(string base64Input
                               , string publicKey)
        {
            var bytesToDecrypt = Convert.FromBase64String(base64Input);
            var decryptEngine = new Pkcs1Encoding(new RsaEngine());
            using (var txtreader = new StringReader(File.ReadAllText(publicKey)))
            {
                var pemReader = new PemReader(txtreader);
                var pemObject = pemReader.ReadObject();
                X509Certificate _privateKey = (X509Certificate)pemObject;
                decryptEngine.Init(false, _privateKey.GetPublicKey());
            }
            var decrypted = Encoding.UTF8.GetString(decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length));
            return decrypted;
        }




        public string RsaEncryptWithPrivate(string clearText
        , string privateKey)
        {
            var bytesToEncrypt = Encoding.UTF8.GetBytes(clearText);

            var encryptEngine = new Pkcs1Encoding(new RsaEngine());

            using (var txtreader = new StringReader(File.ReadAllText(privateKey)))
            {
                var pemReader = new PemReader(txtreader, new PasswordFinder(sSecret));

                var pemObject = pemReader.ReadObject();

                AsymmetricKeyParameter _privateKey = (AsymmetricKeyParameter)pemObject;

                encryptEngine.Init(true, _privateKey);
            }

            var encrypted = Convert.ToBase64String(encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));
            return encrypted;
        }


        public string RsaEncryptWithPublic(string clearText
, string privateKey)
        {
            var bytesToEncrypt = Encoding.UTF8.GetBytes(clearText);

            var encryptEngine = new Pkcs1Encoding(new RsaEngine());

            using (var txtreader = new StringReader(File.ReadAllText(privateKey)))
            {
                var pemReader = new PemReader(txtreader);

                var pemObject = pemReader.ReadObject();

                X509Certificate keyPair = (X509Certificate)pemObject;

                encryptEngine.Init(true, keyPair.GetPublicKey());
            }

            var encrypted = Convert.ToBase64String(encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));
            return encrypted;
        }



        private class PasswordFinder : IPasswordFinder
        {
            private string password;

            public PasswordFinder(string password)
            {
                this.password = password;
            }


            public char[] GetPassword()
            {
                return password.ToCharArray();
            }
        }
    }
}
