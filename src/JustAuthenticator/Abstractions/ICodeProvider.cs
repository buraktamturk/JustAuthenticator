namespace JustAuthenticator.Token
{
    public interface ICodeProvider
    {
        public ICode New(string hidden = null);

        public ICode Parse(string token, string hidden = null);
    }
}
