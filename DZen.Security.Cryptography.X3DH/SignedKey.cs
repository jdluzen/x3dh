using Chaos.NaCl;

namespace DZen.Security.Cryptography.X3DH
{
    public class SignedKey : PrivateKey
    {
        private readonly ICryptoMethods signer;

        public SignedKey(byte[] privateKey, ICryptoMethods signer = default)
            : base(privateKey)
        {
            this.signer = signer ?? new EdDSAMethods();
        }

        public byte[] Signature { get => signer.Sign(PrivateKeyBytes, this); }

        public bool IsValidSignature => signer.Verify(Signature, PrivateKeyBytes, this);

        public new static SignedKey Create()
        {
            return new SignedKey(GetSecureRandomeBytes(Ed25519.PrivateKeySeedSizeInBytes));
        }
    }
}
