using EncriptaCertMicro;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Json;
using System.Security.Cryptography.X509Certificates;

IConfiguration _config = new ConfigurationBuilder()
                            .AddJsonFile("appSettings.json")
                            .Build();

Console.WriteLine("-------Recupera los certificados------");

var _certkv = new ThorKeyVault(_config["KeyVault:nombrekv"], _config["KeyVault:nombrecertificado"]);
X509Certificate2 _certprivate = await _certkv.GetPrivate();
X509Certificate2 _certpublic = await _certkv.GetPublic();


Console.WriteLine("-------Ejemplo con .net------");

var _procnet = new ThorCryptoNet(_certprivate, _certpublic);
_procnet.Proceso();

Console.WriteLine("-------Ejemplo con Bouncy Castle------");


var _procbouncycastle = new ThorCryptoBouncyCastle();
_procbouncycastle.Proceso();


Console.ReadLine();

/*

pasar de pfx a pem total con password
.\openssl.exe pkcs12 -in C:\DiscoD\Temp\xml\star_thorsolpruebas.pfx -out file.pem
 
pasar a pem sin password
.\openssl.exe pkcs12 -in C:\DiscoD\Temp\xml\star_thorsolpruebas.pfx -out file.pem -nodes 
 
pasar a pem solo pk
.\openssl.exe pkcs12 -in C:\DiscoD\Temp\xml\star_thorsolpruebas.pfx -nocerts -out file.pem

pasar a pem solo certificado
.\openssl.exe pkcs12 -in C:\DiscoD\Temp\xml\star_thorsolpruebas.pfx -clcerts -nokeys -out file.pem

 
 */