using System;

namespace JustAuthenticator.Token
{
    public interface ICode
    {
        public Guid id { get; }

        public IPassword password { get; }

        public string code { get; }
    }
}
