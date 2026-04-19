package com.example;

import javax.crypto.Cipher;

/**
 * Fixture for SC-JAVA-CRYPTO-001. The Cipher.getInstance call on line 10
 * must be detected by the SAST engine as a weak-crypto finding.
 */
public class WeakCryptoDES {
    public void bad() throws Exception {
        Cipher c = Cipher.getInstance("DES");
        c.init(Cipher.ENCRYPT_MODE, null);
    }
}
