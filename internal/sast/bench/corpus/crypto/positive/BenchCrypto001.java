package bench.BenchCrypto001;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.Key;

public class BenchCrypto001 {
    public byte[] encrypt(byte[] plaintext) throws Exception {
        KeyGenerator keygen = KeyGenerator.getInstance("DES");
        Key key = keygen.generateKey();
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }
}
