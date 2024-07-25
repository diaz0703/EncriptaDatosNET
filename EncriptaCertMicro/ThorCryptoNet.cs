using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace EncriptaCertMicro
{
    public class ThorCryptoNet
    {
        public ThorCryptoNet(X509Certificate2 certpfx, X509Certificate2 certcrt)
        {
            _Certpfx = certpfx;
            _Certcrt = certcrt;
        }
        // Variables 
        //public static string certificateNamePrivate = "C:\\DiscoD\\Temp\\xml\\star_thorsolpruebas.pfx";
        //public static string certificateNamePublic = "C:\\DiscoD\\Temp\\xml\\STAR_thorsolpruebas_com.crt";
        //public static string sSecret = "*123456*";

        private X509Certificate2 _Certpfx;
        private X509Certificate2 _Certcrt;

        public void Proceso()
        {
            string sTextoAEncriptar = "El texto que se encriptará";
            string sEncryptedSecret = string.Empty;
            string sDecryptedSecret = string.Empty;
            string sFirma = string.Empty;
            bool sValida = false;


            // Encryption 
            Console.WriteLine("Original:   {0}", sTextoAEncriptar);
            Console.WriteLine("-------------------OOOOOOOOOOOOOOOOOOO--------------------");
            sEncryptedSecret = EncryptRsaPublico(sTextoAEncriptar);
            Console.WriteLine("Encriptado:   {0}", sEncryptedSecret);

            Console.WriteLine("-------------------OOOOOOOOOOOOOOOOOOO--------------------");

            // Decryption 
            sDecryptedSecret = decryptRsaPrivado(sEncryptedSecret);
            Console.WriteLine("Desencriptado: {0}", sDecryptedSecret);

            Console.WriteLine("-------------------OOOOOOOOOOOOOOOOOOO--------------------");

            // sign 
            sFirma = FirmaRsaPrivado(sTextoAEncriptar);
            Console.WriteLine("Firma del mensaje: {0}", sFirma);
            Console.WriteLine("-------------------OOOOOOOOOOOOOOOOOOO--------------------");

            // validación
            sValida = ValidacionRsaPublico(sTextoAEncriptar, sFirma);
            Console.WriteLine("La validación de la firma: {0}", sValida.ToString());

            Console.WriteLine("-------------------OOOOOOOOOOOOOOOOOOO--------------------");

            ////Display the original data and the decrypted data.
            Console.WriteLine("Termina el proceso.");
        }

        private X509Certificate2 getCertificatePrivado()
        {
            X509Certificate2 cert = new X509Certificate2(_Certpfx);
            //X509Certificate2 cert = _Certpfx;
            return cert;
        }
        private X509Certificate2 getCertificatepublico()
        {
//            X509Certificate2 cert = new X509Certificate2(certificateNamePublic);
            X509Certificate2 cert = new X509Certificate2(_Certcrt);
            return cert;
        }

        private string EncryptRsaPublico(string input)
        {
            string output = string.Empty;
            X509Certificate2 cert = getCertificatepublico();
            using (System.Security.Cryptography.RSA csp = cert.GetRSAPublicKey())
            {
                byte[] bytesData = Encoding.UTF8.GetBytes(input);
                byte[] bytesEncrypted = csp.Encrypt(bytesData, System.Security.Cryptography.RSAEncryptionPadding.OaepSHA512);
                output = Convert.ToBase64String(bytesEncrypted);
            }
            return output;
        }

        private string decryptRsaPrivado(string encrypted)
        {
            string text = string.Empty;
            X509Certificate2 cert = getCertificatePrivado();
            using (System.Security.Cryptography.RSACng csp = (System.Security.Cryptography.RSACng)cert.PrivateKey)
            {
                byte[] bytesEncrypted = Convert.FromBase64String(encrypted);
                byte[] bytesDecrypted = csp.Decrypt(bytesEncrypted, System.Security.Cryptography.RSAEncryptionPadding.OaepSHA512);
                text = Encoding.UTF8.GetString(bytesDecrypted);
            }
            return text;
        }


        private string FirmaRsaPrivado(string encrypted)
        {
            string text = string.Empty;
            X509Certificate2 cert = getCertificatePrivado();
            using (System.Security.Cryptography.RSACng csp = (System.Security.Cryptography.RSACng)cert.PrivateKey)
            {
                byte[] bytesEncrypted = Encoding.UTF8.GetBytes(encrypted);
                byte[] bytesDecrypted = csp.SignData(bytesEncrypted, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                text = Convert.ToBase64String(bytesDecrypted);
            }
            return text;
        }

        private bool ValidacionRsaPublico(string textoverifica,string firma )
        {
            string text = string.Empty;
            X509Certificate2 cert = getCertificatepublico();
            bool _resultadoverifica = false;
            using (System.Security.Cryptography.RSA csp = cert.GetRSAPublicKey())
            {
                byte[] bytesEncrypted = Encoding.UTF8.GetBytes(textoverifica);
                byte[] bytesFirma = Convert.FromBase64String(firma);
                _resultadoverifica = csp.VerifyData(bytesEncrypted, bytesFirma, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
            }
            return _resultadoverifica;
        }


    }
}
