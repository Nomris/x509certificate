using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

using Org.Websn.X509Certificates;
using Org.Websn.X509Certificates.Abstraction;

namespace Tests
{
    public class Core
    {
        private const string StoreName = "test-cache";
        private IX509CertificateStore _store;
        
        [SetUp]
        public void Setup()
        {
            _store = new X509CertificateStore(Path.Combine(Environment.CurrentDirectory, StoreName));
        }

        [TearDown]
        public void Teardown()
        {
            Directory.Delete(Path.Combine(Environment.CurrentDirectory, StoreName), true);
        }

        [Test]
        public void TestNameDetection()
        {
            Console.WriteLine(_store.Name);
            Assert.That(StoreName == _store.Name);
        }

        [Test]
        public void TestCertificatePrivateKey()
        {
            RSA rsa = RSA.Create(4096);
            CertificateRequest req = new CertificateRequest(new X500DistinguishedName("cn=test"), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            X509Certificate2 cer = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddHours(2));


            _store.Store(cer.SerialNumber, cer, true);

            X509Certificate2 retrivedCer = _store.Get(cer.SerialNumber, true);

            Assert.That(retrivedCer.GetRSAPrivateKey().ExportRSAPrivateKey().SequenceEqual(rsa.ExportRSAPrivateKey()));
        }

        [Test]
        public void TestCertificatePublicKey()
        {
            RSA rsa = RSA.Create(4096);
            CertificateRequest req = new CertificateRequest(new X500DistinguishedName("cn=test"), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            X509Certificate2 cer = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddHours(2));


            _store.Store(cer.SerialNumber, cer, true);

            X509Certificate2 retrivedCer = _store.Get(cer.SerialNumber);

            Assert.That(retrivedCer.GetRSAPublicKey().ExportRSAPublicKey().SequenceEqual(rsa.ExportRSAPublicKey()));
        }
    }
}
