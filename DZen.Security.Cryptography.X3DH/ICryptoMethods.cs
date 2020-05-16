namespace DZen.Security.Cryptography.X3DH
{
    public interface ICryptoMethods
    {
        byte[] Sign(byte[] data, PrivateKey privateKey);
        bool Verify(byte[] signature, byte[] data, PublicKey publicKey);
        byte[] KeyExchange(PublicKey publicKey0, PublicKey publicKey1);
        byte[] DeriveKey(byte[] info);
        byte[] DomainSeparationBytes { get; }
    }
}
