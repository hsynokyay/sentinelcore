package com.example;

/**
 * VULNERABLE: multiple hardcoded secrets that must be detected by
 * SC-JAVA-SECRET-001.
 */
public class HardcodedSecretVulnerable {

    private static final String API_KEY = "sk-live-abcdef1234567890abcdef";
    private static final String DB_PASSWORD = "Super$ecretP@ss2024!";
    private static final String JWT_SECRET = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";

    public void connect() {
        String authToken = "ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8";
    }
}
