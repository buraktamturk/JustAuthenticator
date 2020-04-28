namespace JustAuthenticator.Token
{
    public class DefaultPasswordProvider : IPasswordProvider
    {
        public IPassword Generate(string clearPassword)
        {
            return new Password(clearPassword);
        }

        private class Password : IPassword
        {
            private readonly string clearText;

            public string Hashed => BCrypt.Net.BCrypt.HashPassword(this.clearText);

            public Password(string clearText)
            {
                this.clearText = clearText;
            }

            public bool Compare(string hashedPassword)
            {
                return BCrypt.Net.BCrypt.Verify(this.clearText, hashedPassword);
            }
        }
    }
}
