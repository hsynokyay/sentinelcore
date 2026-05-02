package bench.BenchCryptoSafe001;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import java.security.Key;
import java.security.SecureRandom;

public class BenchCryptoSafe001 {
    public byte[] encrypt(byte[] plaintext) throws Exception {
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        Key key = keygen.generateKey();
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(plaintext);
    }
}
