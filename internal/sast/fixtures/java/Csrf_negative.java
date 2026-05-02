import java.security.MessageDigest;

public class CsrfNegative {
    public boolean verifyCsrf(String submitted, String stored) {
        return MessageDigest.isEqual(submitted.getBytes(), stored.getBytes());
    }
}
