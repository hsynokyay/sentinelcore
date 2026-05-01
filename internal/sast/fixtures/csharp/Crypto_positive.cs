// internal/sast/fixtures/csharp/Crypto_positive.cs
using System.Security.Cryptography;
using System.Text;

public class CryptoPositive
{
    public static byte[] Hash(string input)
    {
        using var md5 = MD5.Create();
        return md5.ComputeHash(Encoding.UTF8.GetBytes(input));
    }
}
