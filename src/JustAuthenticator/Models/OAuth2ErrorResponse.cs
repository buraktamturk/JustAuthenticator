
using Microsoft.AspNetCore.Http;

namespace JustAuthenticator.Models
{
    public record OAuth2ErrorResponse(string error, string? error_description)
    {
        public string code => error;
    }
}
