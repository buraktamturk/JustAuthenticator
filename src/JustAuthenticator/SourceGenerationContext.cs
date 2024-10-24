using System.Text.Json.Serialization;
using JustAuthenticator.Models;

namespace JustAuthenticator;

[JsonSourceGenerationOptions()]
[JsonSerializable(typeof(TokenResponse))]
[JsonSerializable(typeof(OAuth2ErrorResponse))]
internal partial class SourceGenerationContext : JsonSerializerContext
{
}