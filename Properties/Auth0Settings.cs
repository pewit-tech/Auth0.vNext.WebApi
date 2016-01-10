using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Auth0.vNext.WebApi
{
    public class Auth0Settings
    {
        public string Domain { get; set; }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public string SigningCertificate { get; set; }
    }
}
