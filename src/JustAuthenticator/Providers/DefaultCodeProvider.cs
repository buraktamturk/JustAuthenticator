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

        public ICode New(string hidden = null)
        {
            var id = Guid.NewGuid();
            var password = new byte[16];

            using(var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(password);
            }

            var str = String.Concat(Array.ConvertAll(password, x => x.ToString("X2")));

            return new Code
            {
                id = id,
                password = passwordProvider.Generate(str + (hidden ?? "")),
                code = id.ToString("N") + str
            };
        }

        public ICode Parse(string token, string hidden = null)
        {
            if(token.Length != 64 || !Guid.TryParseExact(token.Substring(0, 32), "N", out var id))
            {
                return null;
            }

            return new Code
            {
                id = id,
                password = passwordProvider.Generate(token.Substring(32) + (hidden ?? "")),
                code = token
            };
        }

        private class Code : ICode
        {
            public Guid id { get; set; }

            public IPassword password { get; set; }

            public string code { get; set; }
        }
    }
}
