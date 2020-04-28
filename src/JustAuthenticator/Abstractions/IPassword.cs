namespace JustAuthenticator.Token
{
    public interface IPassword
    {
        public string Hashed { get; }

        public bool Compare(string hashedPassword);
    }
}
