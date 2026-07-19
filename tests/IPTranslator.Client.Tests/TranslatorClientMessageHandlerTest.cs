using Xunit;
using IPTranslator.Contracts.Messaging;
using IPTranslator.Client.Messaging;
using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Text;

namespace IPTranslator.Client.Tests
{
    public class TranslatorClientMessageHandlerTest
    {
        [Fact]
        public void TestEncryptDecryptGcm()
        {
            var key = new byte[32];
            RandomNumberGenerator.Fill(key);
            var data = Encoding.UTF8.GetBytes("Hello, World!");
            var aad = TranslatorClientMessageHandler.RequestAad("req-0", "key-0");

            var (nonce, encrypted) = TranslatorClientMessageHandler.EncryptGcm(key, data, aad);
            Assert.Equal(TranslatorClientMessageHandler.GcmNonceSize, nonce.Length);
            Assert.Equal(data.Length + 16, encrypted.Length); // ciphertext || tag

            var decrypted = TranslatorClientMessageHandler.DecryptGcm(key, nonce, encrypted, aad);
            Assert.Equal("Hello, World!", Encoding.UTF8.GetString(decrypted)); // no padding to strip
        }

        [Fact]
        public void TestGcmDetectsTampering()
        {
            var key = new byte[32];
            RandomNumberGenerator.Fill(key);
            var data = Encoding.UTF8.GetBytes("Hello, World!");
            var aad = TranslatorClientMessageHandler.RequestAad("req-0", "key-0");
            var (nonce, encrypted) = TranslatorClientMessageHandler.EncryptGcm(key, data, aad);

            // flipped ciphertext bit
            var tampered = (byte[])encrypted.Clone();
            tampered[0] ^= 0x01;
            Assert.Throws<InvalidOperationException>(() =>
                { TranslatorClientMessageHandler.DecryptGcm(key, nonce, tampered, aad); });

            // tampered envelope metadata (different AAD)
            var otherAad = TranslatorClientMessageHandler.RequestAad("req-1", "key-0");
            Assert.Throws<InvalidOperationException>(() =>
                { TranslatorClientMessageHandler.DecryptGcm(key, nonce, encrypted, otherAad); });
        }

        [Fact]
        public void TestResponseAadBindsBillingFields()
        {
            var message = new TranslatorResponseMessage
            {
                request_id = "req-0",
                key_id = "key-0",
                request_type = TranslatorRequestTypeEnum.translate_align,
                consumed_units = 3,
                object_id = new byte[] { 0x56, 0x78 }
            };
            // must match ipt-service message.py response_aad
            Assert.Equal("iptv3-rsp:v1:req-0:key-0:translate_align:3:Vng=",
                Encoding.UTF8.GetString(TranslatorClientMessageHandler.ResponseAad(message)));

            message.object_id = null;
            message.consumed_units = 0;
            Assert.Equal("iptv3-rsp:v1:req-0:key-0:translate_align:0:",
                Encoding.UTF8.GetString(TranslatorClientMessageHandler.ResponseAad(message)));
        }

        [Fact]
        public void TestNewWithPublicKey()
        {
            var sut = new TranslatorClientMessageHandler(DevKeys.PublicKeyBase64);
            Assert.True(sut.IsEncrypted);
        }

        [Fact]
        public void TestBuildEncryptedRequest()
        {
            var sut = new TranslatorClientMessageHandler(DevKeys.PublicKeyBase64);
            var request = sut.BuildRequest(new TranslatorRequestBody
            {
                type = TranslatorRequestTypeEnum.probe,
                scope_key = "1",
                src_lang = "en",
                src_text = new string[0],
            });

            Assert.NotNull(request.key_id);
            Assert.NotNull(request.encrypted_key);
            Assert.Equal(XWingKem.CiphertextSize, request.encrypted_key.Length);
            Assert.NotNull(request.entropy);
            Assert.Equal(TranslatorClientMessageHandler.GcmNonceSize, request.entropy.Length); // AES-GCM nonce
            Assert.NotEmpty(request.maybe_encrypted_body);
        }

        [Fact]
        public void TestEncryptedBodyIsConfidential()
        {
            var sut = new TranslatorClientMessageHandler(DevKeys.PublicKeyBase64);
            var secret = "VerySecretSourceText";
            var request = sut.BuildRequest(new TranslatorRequestBody
            {
                type = TranslatorRequestTypeEnum.translate,
                scope_key = "1",
                src_lang = "en",
                src_text = new[] { secret },
                trg_lang = "de",
                trg_text = new[] { "" },
            });

            var wire = Encoding.UTF8.GetString(request.maybe_encrypted_body);
            Assert.DoesNotContain(secret, wire);
        }

        [Fact]
        public void TestDecodeMessage()
        {
            var messageJson = Encoding.UTF8.GetString(unencryptedResponseMessage);
            var message = JsonConvert.DeserializeObject<TranslatorResponseMessage>(messageJson);

            var sut = new TranslatorClientMessageHandler(null);
            var (body, requestId) = sut.ParseResponse(message);

            Assert.NotNull(body);
            Assert.NotNull(body.translations);
            Assert.Equal("111a5e56ed964deebe55b8e20d57db14", requestId);
        }

        byte[] unencryptedResponseMessage = Convert.FromBase64String("eyJyZXF1ZXN0X2lkIjoiMTExYTVlNTZlZDk2NGRlZWJlNTViOGUyMGQ1N2RiMTQiLCJvYmplY3RfaWQiOiI2Y2QzNTU2ZGViMGRhNTRiY2EwNjBiNGMzOTQ3OTgzOSIsImNvbnN1bWVkX3VuaXRzIjoyLCJ0aW1lX21zIjo4OTYuMTQxMjkwNjY0NjcyOSwidW5zYWZlX2Vycm9yIjpudWxsLCJrZXlfaWQiOm51bGwsImVudHJvcHkiOm51bGwsIm1heWJlX2VuY3J5cHRlZF9ib2R5IjoiZXlKeVpYTjFiSFJmZEhsd1pTSTZJblJ5WVc1emJHRjBhVzl1YzE5MGIzQmZheUlzSW1WeWNtOXlYMlJsZEdGcGJITWlPbTUxYkd3c1xuSW1Gc2JHOTNaV1JmWW1WaGJYTWlPalFzSW5SeVlXNXpiR0YwYVc5dWN5STZXM3NpYzJOdmNtVWlPaTB3TGpFNU56RXlOVGszTVRNeFxuTnpJNU1USTJMQ0owWlhoMElqb2lTR0ZzYkc4c0lGZGxiSFFoSWl3aWNtRnVaMlZ6SWpwYld6QXNOVjBzV3pVc01WMHNXellzTlYwc1xuV3pFeExERmRMRnN4TWl3d1hWMHNJbXh2WjJsMGN5STZXeTB3TGpRd01qY3hNemMzTlRZek5EYzJOVFlzTFRBdU1URTBOelEyTURrelxuTnpVc0xUQXVNakUwT0RRek56VXNMVEF1TURnMU9UTTNOU3d0TUM0d01EZ3pNREEzT0RFeU5WMHNJbk4wYjNCZmNtVmhjMjl1SWpvaVxuYzNSdmNGOWpiMjVrYVhScGIyNGlmVjBzSW1Gc2FXZHViV1Z1ZEhNaU9tNTFiR3g5XG4ifQ==");
    }
}
