namespace JustAuthenticator.Token
{
    public interface IPasswordProvider
    {
        public IPassword Generate(string clearPassword);
    }
}
