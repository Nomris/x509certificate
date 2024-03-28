using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Org.Websn.X509Certificates.Abstraction
{
    public interface IX509CertificateStore
    {
        string Name { get; }

        X509Certificate2 Get(string name, bool includePrivateKey = false);

        void Store(string name, X509Certificate2 certificate, bool includePrivateKey = true);
    }
}
