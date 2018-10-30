namespace CipherService_NetCore.Services
{
    public interface ICipherService
    {
        /// <summary>
        /// Encrypt a string.
        /// </summary>
        /// <param name="text"></param>
        /// <param name="offset"></param>
        /// <returns>
        /// Encrypted string.
        /// </returns>
        string CaesarEncrypt(string text, int offset);

        /// <summary>
        /// Decrypt a caesar string.
        /// </summary>
        /// <param name="text">
        /// Content to be encrypted.
        /// </param>
        /// <param name="offset">
        /// Cipher shift offset.
        /// </param>
        /// <returns>
        /// Decrypted string.
        /// </returns>
        string CaesarDecrypt(string text, int offset);

        /// <summary>
        /// Encrypt a string.
        /// </summary>
        /// <param name="text">
        /// Content to be encrypted.
        /// </param>
        /// <param name="salt">
        /// Salt associated with the encrypted string.
        /// </param>
        /// <returns>
        /// Encrypted string.
        /// </returns>
        string Encrypt(string text, string salt);

        /// <summary>
        /// Decrypt a string.
        /// </summary>
        /// <param name="text">
        /// Content to be decrypted.
        /// </param>
        /// <param name="salt">
        /// Salt associated with the encrypted string.
        /// </param>
        /// <returns>
        /// Decrypted string.
        /// </returns>
        string Decrypt(string text, string salt);

        /// <summary>
        /// Generate a random salt.
        /// </summary>
        /// <param name="byteSize">Salt byte size</param>
        /// <returns>Salt string.</returns>
        string GenerateSalt(int byteSize = (128/8));
    }
}