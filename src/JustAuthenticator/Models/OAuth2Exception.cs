using System;
using System.Runtime.Serialization;

namespace JustAuthenticator
{
    public class OAuth2Exception(string error, string? errorDescription) : Exception(errorDescription is null ? error : $"{error}: {errorDescription}")
    {
        public string Error { get; } = error;
        
        public string? ErrorDescription { get; } = errorDescription;
    }
    
    public sealed class InvalidClientException()
        : OAuth2Exception("invalid_client", "Client authentication failed due to missing or invalid client_id");
    
    public sealed class InvalidGrantException()
        : OAuth2Exception("invalid_grant", "The provided authorization grant is invalid, expired, revoked, or does not match the redirection URI used in the authorization request");
    
    public sealed class UnsupportedGrantTypeException()
        : OAuth2Exception("unsupported_grant_type", "The authorization grant type is not supported by the authorization server");
}
