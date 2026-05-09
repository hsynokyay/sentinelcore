// internal/sast/fixtures/csharp/Crypto_negative.cs
using System.Security.Cryptography;
using System.Text;

public class CryptoNegative
{
    public static byte[] Hash(string input)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(Encoding.UTF8.GetBytes(input));
    }
}
