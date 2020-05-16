using System;
using System.Collections.Generic;
using System.Text;

namespace DZen.Security.Cryptography.X3DH
{
    public class KeyBundle
    {
        /// <summary>
        /// IKB
        /// </summary>
        public PublicKey IdentityKey { get; set; }
        /// <summary>
        /// SPKB
        /// </summary>
        public SignedKey Prekey { get; set; }
        /// <summary>
        /// OPKB
        /// </summary>
        public IList<PrivateKey> OneTimePrekeys { get; set; }
    }
}
