import java.util.Random;

public class SessionPositive {
    private static final Random RNG = new Random();

    public String newSessionId() {
        byte[] buf = new byte[16];
        RNG.nextBytes(buf);
        return java.util.Base64.getEncoder().encodeToString(buf);
    }
}
