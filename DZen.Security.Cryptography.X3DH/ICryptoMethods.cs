namespace DZen.Security.Cryptography.X3DH
{
    public interface ICryptoMethods
    {
        byte[] Sign(byte[] data, PrivateKey privateKey);
        bool Verify(byte[] signature, byte[] data, PublicKey publicKey);
        byte[] KeyExchange(PublicKey publicKey, PrivateKey privateKey);
        (byte[] ciphertext, byte[] nonce) Encrypt(byte[] plaintext, byte[] key, byte[] nonce = default);
        byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] nonce);
        byte[] DeriveKey(byte[] info);
        byte[] DomainSeparationBytes { get; }
    }
}
