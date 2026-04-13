package bench.BenchCrypto002;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class BenchCrypto002 {
    public byte[] hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes());
    }
}
