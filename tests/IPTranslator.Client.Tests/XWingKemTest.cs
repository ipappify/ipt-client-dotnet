using Xunit;
using IPTranslator.Client.Messaging;

namespace IPTranslator.Client.Tests
{
    public class XWingKemTest
    {
        private static byte[] DevPublicKey => Convert.FromBase64String(DevKeys.PublicKeyBase64);

        [Fact]
        public void TestEncryptKeySizes()
        {
            var (key, encryptedKey) = XWingKem.EncryptKey(DevPublicKey);
            Assert.Equal(XWingKem.KeySize, key.Length);
            Assert.Equal(XWingKem.CiphertextSize, encryptedKey.Length);
        }

        [Fact]
        public void TestEncryptKeyIsRandomized()
        {
            var (key1, ct1) = XWingKem.EncryptKey(DevPublicKey);
            var (key2, ct2) = XWingKem.EncryptKey(DevPublicKey);
            Assert.NotEqual(key1, key2);
            Assert.NotEqual(ct1, ct2);
        }

        [Fact]
        public void TestInvalidPublicKeySizeThrows()
        {
            Assert.Throws<ArgumentException>(() => XWingKem.EncryptKey(new byte[XWingKem.PublicKeySize - 1]));
            Assert.Throws<ArgumentException>(() => XWingKem.EncryptKey(null));
        }
    }
}
