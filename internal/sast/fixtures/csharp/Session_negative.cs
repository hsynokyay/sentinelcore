using System;
using System.Security.Cryptography;

public class SessionNegative
{
    public string NewSessionId()
    {
        var buf = RandomNumberGenerator.GetBytes(16);
        return Convert.ToBase64String(buf);
    }
}
