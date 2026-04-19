package bench.BenchCrypto003;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.Key;

public class BenchCrypto003 {
    public byte[] encrypt(byte[] plaintext) throws Exception {
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        Key key = keygen.generateKey();
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }
}
