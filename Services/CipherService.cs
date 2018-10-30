using System;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace CipherService_NetCore.Services
{
    public class CipherService : ICipherService
    {
        public static int LengthOfAlpha => alpha.Length;
        private static char[] alpha = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
            'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '5', '6', '7', '8', '9', '0',
            '.', ',', '?', '/', '\\', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-'
        };

        private readonly IDataProtectionProvider _dataProtectionProvider;

        public CipherService(IDataProtectionProvider dataProtectionProvider)
        {
            _dataProtectionProvider = dataProtectionProvider;
        }

        public string CaesarEncrypt(string text, int offset)
        {
            CaesarArgumentValidation(text, offset);

            var input_array = text.ToCharArray();

            for (int j = 0; j < input_array.Length; j++)
            {
                for (int i = 0; i < alpha.Length; i++)
                {
                    if (input_array[j] == alpha[i])
                    {
                        input_array[j] = alpha[(i + offset) % alpha.Length];
                        break;
                    }
                }
            }

            return string.Join(string.Empty, input_array);
        }

        public string CaesarDecrypt(string text, int offset)
        {
            CaesarArgumentValidation(text, offset);
            
            return CaesarEncrypt(text, alpha.Length - offset);
        }

        public string Encrypt(string text, string salt)
        {
            CipherArgumentValidation(text, salt);

            var protector = _dataProtectionProvider.CreateProtector(salt);
            return protector.Protect(text);
        }

        public string Decrypt(string text, string salt)
        {
            CipherArgumentValidation(text, salt);

            var protector = _dataProtectionProvider.CreateProtector(salt);
            return protector.Unprotect(text);
        }

        public string GenerateSalt(int byteSize = (128/8))
        {
            if (byteSize <= 0)
                throw new ArgumentOutOfRangeException(nameof(byteSize), "Must be more than 0");

            byte[] salt = new byte[byteSize];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(salt);
            return Convert.ToBase64String(salt);
        }
        
        private void CaesarArgumentValidation(string text, int offset)
        {
            if (string.IsNullOrEmpty(text))
                throw new ArgumentNullException(nameof(text), "text cannot be a null reference");
            if (offset <= 0)
                throw new ArgumentOutOfRangeException("Must be more than 0", nameof(offset));
            if (offset >= alpha.Length)
                throw new ArgumentOutOfRangeException($"Must be less than {alpha.Length}", nameof(offset));
        }

        private void CipherArgumentValidation(string text, string salt)
        {
            if (string.IsNullOrEmpty(text))
                throw new ArgumentNullException(nameof(text), "text cannot be a null reference");
            if (string.IsNullOrEmpty(salt))
                throw new ArgumentNullException(nameof(salt), "salt cannot be a null reference");
        }
    }
}