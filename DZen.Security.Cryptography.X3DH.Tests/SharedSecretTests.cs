using FluentAssertions;
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
            byte[] dh2 = crypto.KeyExchange(bob.IdentityKey, eka);
            byte[] dh3 = crypto.KeyExchange(eka, bob.Prekey);

            byte[] sk = crypto.DeriveKey(dh1.Concat(dh2, dh3));

            //eka = default;//alice deletes this, bob needs it below
            dh1 = dh2 = dh3 = default;

            byte[] ad = ika.PublicKeyBytes.Concat(bob.IdentityKey.PublicKeyBytes);//TODO: this is recommended to have a more standardized format

            (byte[] ciphertext, byte[] nonce) = crypto.Encrypt(ad, sk);//output is sent to bob

            KeyBundleResponse response = new KeyBundleResponse
            {
                Ciphertext = ciphertext,
                EphemeralKey = eka,
                PrekeyHash = default,//TODO:
                Identity = ika
            };

            dh1 = crypto.KeyExchange(response.Identity, bob.Prekey);
            dh2 = crypto.KeyExchange(response.EphemeralKey, bob.IdentityKey as PrivateKey);
            dh3 = crypto.KeyExchange(bob.Prekey, eka);

            byte[] bobsSk = crypto.DeriveKey(dh1.Concat(dh2, dh3));

            dh1 = dh2 = dh3 = default;

            byte[] bobsAd = ika.PublicKeyBytes.Concat(bob.IdentityKey.PublicKeyBytes);

            byte[] plaintext = crypto.Decrypt(ciphertext, bobsSk, nonce);

            plaintext.Should().BeEquivalentTo(ad);
        }
    }
}
