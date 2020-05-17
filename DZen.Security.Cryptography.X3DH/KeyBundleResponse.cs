using System;
using System.Collections.Generic;
using System.Text;

namespace DZen.Security.Cryptography.X3DH
{
    public class KeyBundleResponse
    {
        public PublicKey Identity { get; set; }
        public PrivateKey EphemeralKey { get; set; }
        public byte[] PrekeyHash { get; set; }
        public byte[] Ciphertext { get; set; }
    }
}
