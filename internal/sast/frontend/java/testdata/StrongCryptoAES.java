package com.example;

import javax.crypto.Cipher;

/**
 * Negative fixture: AES/GCM/NoPadding is a strong construction and the
 * SAST engine must NOT flag this file.
 */
public class StrongCryptoAES {
    public void good() throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, null);
    }
}
