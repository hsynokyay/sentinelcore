package bench.BenchSecret003;

import java.util.Base64;

public class BenchSecret003 {
    private static final String JWT_SECRET = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.sig";

    public boolean verifyToken(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return false;
        }
        String payload = new String(Base64.getDecoder().decode(parts[1]));
        return payload.contains(JWT_SECRET);
    }
}
