package bench.BenchCryptoSafe002;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class BenchCryptoSafe002 {
    public byte[] hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(password.getBytes());
    }
}
