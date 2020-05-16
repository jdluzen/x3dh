using FluentAssertions;
using System;
using Xunit;

namespace DZen.Security.Cryptography.X3DH.Tests
{
    public class SignatureTests
    {
        [Fact]
        public void SignedKey_Validates()
        {
            PrivateKey privKey = PrivateKey.Create();

            new SignedKey(privKey.PrivateKeyBytes, new EdDSAMethods()).IsValidSignature.Should().BeTrue();
        }
    }
}
