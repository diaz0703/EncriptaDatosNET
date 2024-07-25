using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using System.Security.Cryptography.X509Certificates;

namespace EncriptaCertMicro
{
    public class ThorKeyVault
    {
        private readonly string _kvname;
        private readonly string _certnombre;

        public ThorKeyVault(string kvname, string certnombre)
        {
            _kvname = kvname;
            _certnombre = certnombre;
        }


        public async Task<X509Certificate2> GetPrivate()
        {

            string certificateName = _certnombre;
            var keyVaultName = _kvname;
            var kvUri = $"https://{keyVaultName}.vault.azure.net";

            var client = new CertificateClient(new Uri(kvUri), new DefaultAzureCredential());
            Console.WriteLine($"Recuperando el certificado privado de {keyVaultName}.");
            var certificate = await client.DownloadCertificateAsync(certificateName);

            Console.WriteLine($"La versión del certificado es '{certificate.Value.GetSerialNumberString()}'.");

            return new X509Certificate2(certificate.Value);
        }

        public async Task<X509Certificate2> GetPublic()
        {
            string certificateName = _certnombre;
            var keyVaultName = _kvname;
            var kvUri = $"https://{keyVaultName}.vault.azure.net";

            var client = new CertificateClient(new Uri(kvUri), new DefaultAzureCredential());
            Console.WriteLine($"Recupera el certificado publico {keyVaultName}.");
            var certificate = await client.GetCertificateAsync(certificateName);
            Console.WriteLine($"La versión del certificado es '{certificate.Value.Properties.Version}'.");
            return new X509Certificate2(certificate.Value.Cer);
        }
    }
}
