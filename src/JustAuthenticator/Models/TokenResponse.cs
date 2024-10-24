namespace JustAuthenticator
{
    public record TokenResponse(string access_token, string token_type, int expires_in, string? refresh_token = null);
}
