using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

using Org.Websn.X509Certificates.Abstraction;

namespace Org.Websn.X509Certificates
{
    public sealed class X509CertificateStore : IX509CertificateStore
    {
        private readonly string _directory;
        private readonly string _name;

        public string Name => _name;

        public X509CertificateStore(string directory)
        {
            if (!Directory.Exists(directory)) Directory.CreateDirectory(directory);
            _directory = directory;
            _name = Path.GetFileName(_directory);
        }

        public X509Certificate2 Get(string name, bool includePrivateKey = false)
        {
            ArgumentNullException.ThrowIfNull(name, nameof(name));

            string basePath = Path.Combine(_directory, name);

            if (!File.Exists(basePath + ".cer")) throw new KeyNotFoundException("Faild to find Certificate with name: " + name);

            X509Certificate2 cert = new X509Certificate2(Convert.FromBase64String(File.ReadAllText(basePath + ".cer")));
            if (!includePrivateKey) return cert;

            if (!File.Exists(basePath + ".key")) return cert;

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportRSAPrivateKey(Convert.FromBase64String(File.ReadAllText(basePath + ".key")), out _);
            
            return cert.CopyWithPrivateKey(rsa);
        }

        public void Store(string name, X509Certificate2 certificate, bool includePrivateKey = true)
        {
            File.WriteAllText(Path.Combine(_directory, name + ".cer"), Convert.ToBase64String(certificate.Export(X509ContentType.Cert)));
            if (!includePrivateKey || !certificate.HasPrivateKey) return;
            File.WriteAllText(Path.Combine(_directory, name + ".key"), Convert.ToBase64String(certificate.GetRSAPrivateKey().ExportRSAPrivateKey()));
        }
    }
}
