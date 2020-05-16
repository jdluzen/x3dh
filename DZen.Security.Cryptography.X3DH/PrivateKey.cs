using Chaos.NaCl;
using System;
using System.Security.Cryptography;

namespace DZen.Security.Cryptography.X3DH
{
    public class PrivateKey : PublicKey
    {
        private byte[] privateKey;
        public byte[] PrivateKeyBytes { get => privateKey; }

        internal byte[] privateKeyExpanded;

        public PrivateKey(byte[] privateKey)
            : base(Ed25519.PublicKeyFromSeed(privateKey))
        {
            if ((privateKey?.Length ?? 0) != Ed25519.PrivateKeySeedSizeInBytes)
                throw new ArgumentException($"{nameof(privateKey)}.Length must be {Ed25519.PrivateKeySeedSizeInBytes}");

            this.privateKey = privateKey;
            privateKeyExpanded = Ed25519.ExpandedPrivateKeyFromSeed(privateKey);
        }

        public static PrivateKey Create()
        {
            return new PrivateKey(GetSecureRandomeBytes(Ed25519.PrivateKeySeedSizeInBytes));
        }

        protected static byte[] GetSecureRandomeBytes(int size)
        {
            byte[] randomeBytes = new byte[Ed25519.PrivateKeySeedSizeInBytes];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(randomeBytes);
            return randomeBytes;
        }
    }
}
