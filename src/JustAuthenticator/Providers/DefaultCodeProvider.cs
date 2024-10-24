using System;
using System.Security.Cryptography;

namespace JustAuthenticator.Token
{
    public class DefaultCodeProvider : ICodeProvider
    {
        private readonly IPasswordProvider passwordProvider;

        public DefaultCodeProvider(IPasswordProvider passwordProvider)
        {
            this.passwordProvider = passwordProvider;
        }

        public ICode New(string? hidden = null)
        {
            var id = Guid.NewGuid();
            var password = new byte[16];

            RandomNumberGenerator.Fill(password);

            var str = String.Concat(Array.ConvertAll(password, x => x.ToString("X2")));
            var _password = passwordProvider.Generate(str + (hidden ?? ""));

            return new Code(id, _password, id.ToString("N") + str);
        }

        public ICode? Parse(string token, string? hidden = null)
        {
            if(token.Length != 64 || !Guid.TryParseExact(token.Substring(0, 32), "N", out var id))
            {
                return null;
            }

            var password = passwordProvider.Generate(token.Substring(32) + (hidden ?? ""));

            return new Code(id, password, token);
        }

        private class Code(Guid id, IPassword password, string code) : ICode
        {
            public Guid id { get; } = id;

            public IPassword password { get; } = password;

            public string code { get; } = code;
        }
    }
}
