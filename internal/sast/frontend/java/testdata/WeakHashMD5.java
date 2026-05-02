package com.example;

import java.security.MessageDigest;

/**
 * Fixture for the second SC-JAVA-CRYPTO-001 pattern (MessageDigest.getInstance
 * with a broken hash). The call on line 10 must be detected.
 */
public class WeakHashMD5 {
    public byte[] hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }
}
