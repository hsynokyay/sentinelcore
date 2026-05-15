package com.test.vuln;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Random;

/**
 * CWE-327: Use of Broken/Risky Cryptographic Algorithm
 * CWE-326: Inadequate Encryption Strength
 * CWE-330: Insufficient Randomness
 * CWE-321: Hardcoded Cryptographic Key
 * CWE-759: Use of One-Way Hash without Salt
 */
public class CryptoVulnerabilities {

    // CWE-321: Hardcoded crypto key
    private static final String SECRET_KEY = "MySecretKey12345";
    private static final String AES_KEY = "0123456789abcdef";
    private static final String JWT_SECRET = "supersecret";

    // CWE-798: Hardcoded credentials
    private static final String API_KEY = "sk-1234567890abcdefghijklmnop";
    private static final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
    private static final String AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    // VULN: Weak hashing - MD5
    public String hashPasswordMD5(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return bytesToHex(hash);
    }

    // VULN: Weak hashing - SHA1
    public String hashWithSHA1(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return bytesToHex(md.digest(input.getBytes()));
    }

    // VULN: Hash without salt
    public String hashSimple(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return bytesToHex(md.digest(password.getBytes()));
    }

    // VULN: DES - broken algorithm
    public byte[] encryptWithDES(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        SecretKeySpec key = new SecretKeySpec("12345678".getBytes(), "DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data.getBytes());
    }

    // VULN: AES with ECB mode (no IV, deterministic)
    public byte[] encryptECB(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(AES_KEY.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data.getBytes());
    }

    // VULN: AES-CBC with static IV
    public byte[] encryptCBCStaticIV(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(AES_KEY.getBytes(), "AES");
        IvParameterSpec iv = new IvParameterSpec(new byte[16]); // All zeros IV
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data.getBytes());
    }

    // VULN: RC4 - broken cipher
    public byte[] encryptRC4(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("RC4");
        SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(), "RC4");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data.getBytes());
    }

    // VULN: Blowfish with weak key
    public byte[] encryptBlowfish(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("Blowfish");
        SecretKeySpec key = new SecretKeySpec("weak".getBytes(), "Blowfish");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data.getBytes());
    }

    // VULN: Insecure random for security purposes
    public String generateToken() {
        Random random = new Random();
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            token.append(random.nextInt(10));
        }
        return token.toString();
    }

    // VULN: Math.random for security
    public String generateSessionId() {
        return String.valueOf(Math.random()).substring(2);
    }

    // VULN: Predictable seed
    public String generatePassword() {
        Random rand = new Random(System.currentTimeMillis());
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            sb.append((char)('a' + rand.nextInt(26)));
        }
        return sb.toString();
    }

    // VULN: Small RSA key size
    public KeyPair generateRSAKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(512); // Way too small
        return kpg.generateKeyPair();
    }

    // VULN: Trusting all SSL certificates
    public void disableSSLVerification() throws Exception {
        javax.net.ssl.TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[]{
            new javax.net.ssl.X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
            }
        };
        javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new SecureRandom());
        javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        // VULN: Hostname verifier accepts all
        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
