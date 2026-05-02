package com.example;

import javax.crypto.Cipher;

/**
 * AES-in-ECB violation. The cipher algorithm is strong (AES) but ECB mode
 * leaks structure. The SC-JAVA-CRYPTO-001 regex matches "/ECB" anywhere in
 * the mode string, so this must be flagged at line 9.
 */
public class ECBModeViolation {
    public void encrypt() throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
    }
}
