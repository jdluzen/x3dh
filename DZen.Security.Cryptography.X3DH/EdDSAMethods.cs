using Chaos.NaCl;
using System;

namespace DZen.Security.Cryptography.X3DH
{
    public class EdDSAMethods : ICryptoMethods
    {
        internal static readonly byte[] empty = new byte[0];
        internal static readonly byte[] empty256Salt = new byte[32];
        private static readonly byte[] x25519DomainBytes = new byte[32];

        static EdDSAMethods()
        {
            Array.Fill<byte>(x25519DomainBytes, 0xFF);
        }

        public byte[] DomainSeparationBytes => x25519DomainBytes;

        public byte[] DeriveKey(byte[] info)
        {
            using Hkdf hkdf = new Hkdf();
            return hkdf.DeriveKey(empty256Salt, hkdf.HashSize == empty256Salt.Length ? empty256Salt : new byte[hkdf.HashSize], DomainSeparationBytes.Concat(info), 32);
        }

        public byte[] KeyExchange(PublicKey publicKey0, PublicKey publicKey1)
        {
            return Ed25519.KeyExchange(publicKey0.PublicKeyBytes, publicKey1.PublicKeyBytes);
        }

        public byte[] Sign(byte[] data, PrivateKey privateKey)
        {
            return Ed25519.Sign(data ?? empty, privateKey.privateKeyExpanded);
        }

        public bool Verify(byte[] signature, byte[] data, PublicKey publicKey)
        {
            return Ed25519.Verify(signature, data ?? empty, publicKey.PublicKeyBytes);
        }
    }
}
