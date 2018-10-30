using System;
using CipherService_NetCore.Services;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace CipherService.Tests
{
    public class TestsSetup
    {
        protected static ICipherService _cipherService;
        protected static string _cipherText = "Hello World";
        protected static int GetRandomCipherOffset() =>
            (new Random()).Next(1, CipherService_NetCore.Services.CipherService.LengthOfAlpha-1);

        [SetUp]
        public void Setup()
        {
            var serviceCollection = new ServiceCollection();

            serviceCollection
                .AddSingleton<ICipherService, CipherService_NetCore.Services.CipherService>()
                .AddDataProtection();

            var serviceProvider = serviceCollection.BuildServiceProvider();

            _cipherService = serviceProvider.GetService<ICipherService>();
        }
    }
}