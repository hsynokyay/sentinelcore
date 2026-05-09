import java.security.SecureRandom;

public class SessionNegative {
    private static final SecureRandom RNG = new SecureRandom();

    public String newSessionId() {
        byte[] buf = new byte[16];
        RNG.nextBytes(buf);
        return java.util.Base64.getEncoder().encodeToString(buf);
    }
}
