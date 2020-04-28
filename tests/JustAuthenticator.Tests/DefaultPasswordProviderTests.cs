using JustAuthenticator.Token;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace JustAuthenticator.Tests
{
    public class DefaultPasswordProviderTests
    {
        private readonly DefaultPasswordProvider provider = new DefaultPasswordProvider();

        [Fact]
        public void TestGenerateAndCompare()
        {
            var password = provider.Generate("TEST");

            Assert.NotNull(password);
            Assert.NotNull(password.Hashed);
            Assert.NotEmpty(password.Hashed);

            var hash1 = password.Hashed;
            var hash2 = password.Hashed;

            Assert.NotEqual(hash1, hash2);

            Assert.True(password.Compare(hash1));
            Assert.True(password.Compare(hash2));

            Assert.True(provider.Generate("TEST").Compare(hash1));
            Assert.False(provider.Generate("Test").Compare(hash1));
            Assert.False(provider.Generate("TeSt").Compare(hash1));
        }
    }
}
