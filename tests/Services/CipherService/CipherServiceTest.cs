namespace CipherService.Tests.Services.CipherService
{
	using System;
    using System.Text;
    using NUnit.Framework;

    [TestFixture]
    public class CipherServiceTest : TestsSetup
    {
        [Test]
        [Order(1)]
        public void AssertThrowsArgumentOutOfRangeException_GenerateSalt()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _cipherService.GenerateSalt(0));
            Assert.Throws<ArgumentOutOfRangeException>(() => _cipherService.GenerateSalt(-1));
        }

        [Test]
        [Order(1)]
        public void AssertThrowsArgumentOutOfRangeException_CaesarEncrypt()
        {
            // Lower
            Assert.Throws<ArgumentOutOfRangeException>(() => _cipherService.CaesarEncrypt(_cipherText, 0));
            Assert.Throws<ArgumentOutOfRangeException>(() => _cipherService.CaesarEncrypt(_cipherText, -1));

            // Upper
            var maxAlphaSize = CipherService_NetCore.Services.CipherService.LengthOfAlpha;
            Assert.Throws<ArgumentOutOfRangeException>(() => _cipherService.CaesarEncrypt(_cipherText, maxAlphaSize));
            Assert.Throws<ArgumentOutOfRangeException>(() => _cipherService.CaesarEncrypt(_cipherText, maxAlphaSize+1));
        }

        [Test]
        [Order(1)]
        public void AssertThrowsArgumentOutOfRangeException_CaesarDecrypt()
        {
            // Lower
            Assert.Throws<ArgumentOutOfRangeException>(() => _cipherService.CaesarDecrypt(_cipherText, 0));
            Assert.Throws<ArgumentOutOfRangeException>(() => _cipherService.CaesarDecrypt(_cipherText, -1));

            // Upper
            var maxAlphaSize = CipherService_NetCore.Services.CipherService.LengthOfAlpha;
            Assert.Throws<ArgumentOutOfRangeException>(() => _cipherService.CaesarDecrypt(_cipherText, maxAlphaSize));
            Assert.Throws<ArgumentOutOfRangeException>(() => _cipherService.CaesarDecrypt(_cipherText, maxAlphaSize+1));
        }

        [Test]
        [Order(1)]
        public void AssertThrowsArgumentNullException_CaesarEncrypt()
        {
            Assert.Throws<ArgumentNullException>(() => _cipherService.CaesarEncrypt(string.Empty, 1));
        }

        [Test]
        [Order(1)]
        public void AssertThrowsArgumentNullException_CaesarDecrypt()
        {
            Assert.Throws<ArgumentNullException>(() => _cipherService.CaesarDecrypt(string.Empty, 1));
        }

        [Test]
        [Order(1)]
        public void AssertThrowsArgumentNullException_Encrypt()
        {
            Assert.Throws<ArgumentNullException>(() => _cipherService.Encrypt(string.Empty, string.Empty));
            Assert.Throws<ArgumentNullException>(() => _cipherService.Encrypt(_cipherText, string.Empty));
            Assert.Throws<ArgumentNullException>(() => _cipherService.Encrypt(string.Empty, _cipherText));
        }

        [Test]
        [Order(1)]
        public void AssertThrowsArgumentNullException_Decrypt()
        {
            Assert.Throws<ArgumentNullException>(() => _cipherService.Decrypt(string.Empty, string.Empty));
            Assert.Throws<ArgumentNullException>(() => _cipherService.Decrypt(_cipherText, string.Empty));
            Assert.Throws<ArgumentNullException>(() => _cipherService.Decrypt(string.Empty, _cipherText));
        }

        [Test]
        [Order(1)]
        public void AssertThrowsCryptographicException_Decrypt()
        {
            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => _cipherService.Decrypt("RandomSalt(", _cipherText));
        }

        [Test]
        [Order(2)]
        public void AssertNotNull_GenerateSalt()
        {
            Assert.NotNull(_cipherService.GenerateSalt());
            Assert.NotNull(_cipherService.GenerateSalt(32));
            Assert.NotNull(_cipherService.GenerateSalt(64));
        }

        [Test]
        [Order(3)]
        public void AssertNotNull_Encrypt()
        {
            var salt = _cipherService.GenerateSalt();
            Assert.NotNull(_cipherService.Encrypt(_cipherText, salt));
        }

        [Test]
        [Order(3)]
        public void AssertNotNull_CaesarEncrypt()
        {
            Assert.NotNull(_cipherService.CaesarEncrypt(_cipherText, GetRandomCipherOffset()));
        }

        [Test]
        [Order(3)]
        public void AssertNotNull_CaesarDecrypt()
        {
            Assert.NotNull(_cipherService.CaesarDecrypt(_cipherText, GetRandomCipherOffset()));
        }

        [Test]
        [Order(3)]
        public void AssertNotNull_Decrypt()
        {
            var randomSalt = _cipherService.GenerateSalt();
            var encrypted = _cipherService.Encrypt(_cipherText, randomSalt);
            Assert.NotNull(_cipherService.Decrypt(encrypted, randomSalt));
        }

        [Test]
        [Order(3)]
        public void AssertAreEqual_EncryptAndDecrypt()
        {
            var randomSalt = _cipherService.GenerateSalt();
            var encrypted = _cipherService.Encrypt(_cipherText, randomSalt);
            var decrypted = _cipherService.Decrypt(encrypted, randomSalt);

            Assert.AreEqual(_cipherText, decrypted);
        }

        [Test]
        [Order(3)]
        public void AssertAreEqual_CaesarEncryptAndCaesarDecrypt()
        {
            var cipherOffset = GetRandomCipherOffset();
            var encrypted = _cipherService.CaesarEncrypt(_cipherText, cipherOffset);
            var decrypted = _cipherService.CaesarDecrypt(encrypted, cipherOffset);

            Assert.AreEqual(_cipherText, decrypted);
        }

        [Test]
        [Order(3)]
        public void AssertAreEqual_EncryptAndCaesarDecrypt()
        {
            var randomSalt = _cipherService.GenerateSalt();
            var cipherOffset = GetRandomCipherOffset();

            var encrypted = _cipherService.Encrypt(_cipherText, randomSalt);
            var caesarEncrypt = _cipherService.CaesarEncrypt(encrypted, cipherOffset);
            var caesarDecrypt = _cipherService.CaesarDecrypt(caesarEncrypt, cipherOffset);
            var decrypted = _cipherService.Decrypt(caesarDecrypt, randomSalt);
        }
    }
}