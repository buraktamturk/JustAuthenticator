using JustAuthenticator.Token;
using Moq;
using System;
using Xunit;

namespace JustAuthenticator.Tests
{
    public class DefaultCodeProviderTests
    {
        private readonly Mock<IPasswordProvider> mockedPasswordProvider;
        private readonly ICodeProvider provider;

        public DefaultCodeProviderTests()
        {
            this.mockedPasswordProvider = new Mock<IPasswordProvider>();
            this.provider = new DefaultCodeProvider(this.mockedPasswordProvider.Object);

            this.mockedPasswordProvider
                .Setup(a => a.Generate(It.IsAny<string>()))
                .Returns<string>(a =>
                {
                    var mockedPassword = new Mock<IPassword>();

                    mockedPassword
                        .Setup(b => b.Compare(a))
                        .Returns(true);

                    mockedPassword
                        .Setup(b => b.Hashed)
                        .Returns(a);

                    return mockedPassword.Object;
                });

        }

        [Fact]
        public void TestGenerateNew()
        {
            var code = provider.New();
            Assert.NotNull(code);

            Assert.NotNull(code.code);
            Assert.NotEmpty(code.code);

            Assert.NotNull(code.password);

            Assert.True(code.password.Compare(code.code.Substring(32)));
            Assert.False(code.password.Compare("Non-sense"));
        }

        [Fact]
        public void TestParse()
        {
            var code = provider.New();
            Assert.NotNull(code);

            var hash = code.password.Hashed;

            var code2 = provider.Parse(code.code);
            Assert.NotNull(code2);

            Assert.Equal(code.id, code2.id);
            Assert.Equal(code.code, code2.code);
            Assert.True(code2.password.Compare(hash));
            Assert.False(code2.password.Compare("Non-sense"));
        }

        [Fact]
        public void TestGenerateNewHidden()
        {
            var code = provider.New("hidden");
            Assert.NotNull(code);

            Assert.NotNull(code.code);
            Assert.NotEmpty(code.code);

            Assert.NotNull(code.password);

            Assert.False(code.password.Compare(code.code.Substring(32)));
            Assert.True(code.password.Compare(code.code.Substring(32) + "hidden"));
            Assert.False(code.password.Compare("Non-sense"));
        }

        [Fact]
        public void TestParseHidden()
        {
            var code = provider.New("hidden");
            Assert.NotNull(code);

            var hash = code.password.Hashed;

            var code2 = provider.Parse(code.code, "hidden");
            Assert.NotNull(code2);

            Assert.Equal(code.id, code2.id);
            Assert.Equal(code.code, code2.code);
            Assert.True(code2.password.Compare(hash));
            Assert.False(code2.password.Compare("Non-sense"));
        }

        [Fact]
        public void TestParseInvalidHidden()
        {
            var code = provider.New("hidden");
            Assert.NotNull(code);

            var hash = code.password.Hashed;

            var code2 = provider.Parse(code.code, "hidden2");
            Assert.NotNull(code2);

            Assert.Equal(code.id, code2.id);
            Assert.Equal(code.code, code2.code);
            Assert.False(code2.password.Compare(hash));
            Assert.False(code2.password.Compare("Non-sense"));
        }
    }
}
