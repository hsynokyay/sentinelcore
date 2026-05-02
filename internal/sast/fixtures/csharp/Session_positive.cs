using System;

public class SessionPositive
{
    private static readonly Random Rng = new Random();

    public string NewSessionId()
    {
        var buf = new byte[16];
        Rng.NextBytes(buf);
        return Convert.ToBase64String(buf);
    }
}
