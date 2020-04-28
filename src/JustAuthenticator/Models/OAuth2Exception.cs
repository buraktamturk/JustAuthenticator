using System;
using System.Runtime.Serialization;

namespace JustAuthenticator
{
    public class OAuth2Exception : Exception
    {
        public OAuth2Exception()
        {
        }

        public OAuth2Exception(string message) : base(message)
        {
        }

        public OAuth2Exception(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected OAuth2Exception(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}
