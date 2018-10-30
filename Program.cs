using System;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.Internal;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;
using System.IO;
using CipherService_NetCore.Services;

namespace CipherService_NetCore
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var serviceCollection = new ServiceCollection();

            serviceCollection
                .AddSingleton<ICipherService, CipherService_NetCore.Services.CipherService>()
                .AddDataProtection();

            var serviceProvider = serviceCollection.BuildServiceProvider();

            // Localize services
            var cipherService = serviceProvider.GetService<ICipherService>();

            string originalText = "Hello World";
            int caesarOffset = (new Random()).Next(1, CipherService_NetCore.Services.CipherService.LengthOfAlpha-1); // Random offset length based on charset.
            
            // Generate Salt
            var salt = cipherService.GenerateSalt(32);
            Console.WriteLine($"Salt value: {salt}");

            // Generate an encrypted string based on text and salt
            var encrypted = cipherService.Encrypt(originalText, salt);
            Console.WriteLine($"Encrypt value: {encrypted}");

            // Generate an encrypted caesar string
            var caesarEncrypted = cipherService.CaesarEncrypt(encrypted, caesarOffset);
            Console.WriteLine($"CaesarEncrypt value: {caesarEncrypted}");

            // Decrypt the caesar string
            var caesarDecrypt = cipherService.CaesarDecrypt(caesarEncrypted, caesarOffset);
            Console.WriteLine($"CaesarDecrypt value: {caesarDecrypt}");

            // Decrypt value from caesarDecrypt and provided salt
            var decrypted = cipherService.Decrypt(caesarDecrypt, salt);
            Console.WriteLine($"Decrypt value: {decrypted}");

            Console.WriteLine("Complete!");
        }
    }
}
