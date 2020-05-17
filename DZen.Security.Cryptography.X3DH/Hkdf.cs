using System;
using System.Security.Cryptography;

namespace DZen.Security.Cryptography.X3DH
{
    //https://gist.github.com/CodesInChaos/8710228
    internal class Hkdf : IDisposable
    {
        Func<byte[], byte[], byte[]> keyedHash;
        HMAC hmac;//originally was HMACSHA256

        public int HashSize { get => hmac.HashSize; }

        public Hkdf(HMAC hmac = default)
        {
            this.hmac = hmac ?? new HMACSHA256();
            keyedHash = (key, message) =>
            {
                this.hmac.Key = key;
                return this.hmac.ComputeHash(message);
            };
        }

        public byte[] Extract(byte[] salt, byte[] inputKeyMaterial)
        {
            return keyedHash(salt, inputKeyMaterial);
        }

        public byte[] Expand(byte[] prk, byte[] info, int outputLength)
        {
            var resultBlock = Array.Empty<byte>();
            var result = new byte[outputLength];
            var bytesRemaining = outputLength;
            for (int i = 1; bytesRemaining > 0; i++)
            {
                var currentInfo = new byte[resultBlock.Length + info.Length + 1];
                Array.Copy(resultBlock, 0, currentInfo, 0, resultBlock.Length);
                Array.Copy(info, 0, currentInfo, resultBlock.Length, info.Length);
                currentInfo[currentInfo.Length - 1] = (byte)i;
                resultBlock = keyedHash(prk, currentInfo);
                Array.Copy(resultBlock, 0, result, outputLength - bytesRemaining, Math.Min(resultBlock.Length, bytesRemaining));
                bytesRemaining -= resultBlock.Length;
            }
            return result;
        }

        public byte[] DeriveKey(byte[] salt, byte[] inputKeyMaterial, byte[] info, int outputLength)
        {
            var prk = Extract(salt, inputKeyMaterial);
            var result = Expand(prk, info, outputLength);
            return result;
        }

        public void Dispose()
        {
            hmac?.Dispose();
            hmac = default;
        }
    }
}
