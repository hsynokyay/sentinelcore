using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

public class JwtPositive
{
    private static readonly string JwtSecret = "supersecretpassword12345"; // SC-CSHARP-JWT-003

    public JwtSecurityToken ReadUnsigned(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        return handler.ReadJwtToken(token); // SC-CSHARP-JWT-001
    }

    public void DisableValidation(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        var p = new TokenValidationParameters
        {
            ValidateSignature = false,
            ValidateLifetime = false,
        };
        handler.ValidateToken(token, p, out _); // SC-CSHARP-JWT-002
    }
}
