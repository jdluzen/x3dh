using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace DZen.Security.Cryptography.X3DH.Tests
{
    public class SharedSecretTests
    {
        /// <summary>
        /// Section 3.3
        /// </summary>
        [Fact]
        public void NoOneTimeKey()
        {
            PrivateKey ika = PrivateKey.Create();
            PrivateKey eka = PrivateKey.Create();

            KeyBundle bob = new KeyBundle
            {
                IdentityKey = PrivateKey.Create(),
                Prekey = SignedKey.Create(),
            };


            ICryptoMethods crypto = new EdDSAMethods();

            byte[] dh1 = crypto.KeyExchange(ika, bob.Prekey);
            byte[] dh2 = crypto.KeyExchange(eka, bob.IdentityKey);
            byte[] dh3 = crypto.KeyExchange(eka, bob.Prekey);

            byte[] sk = crypto.DeriveKey(dh1.Concat(dh2, dh3));


        }
    }
}
