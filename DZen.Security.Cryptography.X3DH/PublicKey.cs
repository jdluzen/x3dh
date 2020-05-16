namespace DZen.Security.Cryptography.X3DH
{
    public class PublicKey
    {
        public byte[] PublicKeyBytes { get; private set; }

        public PublicKey(byte[] publicKey)
        {
            PublicKeyBytes = publicKey;
        }
    }
}
