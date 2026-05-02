package com.example;

import javax.crypto.Cipher;
import java.security.MessageDigest;

/**
 * Mixed fixture: three crypto calls, only the first is a weak-crypto match.
 * The engine must flag exactly one finding at line 11 (DES) and leave the
 * SHA-256 and AES/CBC calls alone.
 */
public class MixedCryptoBatch {
    public void mix() throws Exception {
        Cipher c1 = Cipher.getInstance("DES");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        Cipher c2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
    }
}
