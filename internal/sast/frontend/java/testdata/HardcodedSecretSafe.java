package com.example;

/**
 * SAFE: no actual hardcoded secrets — only placeholder values, env lookups,
 * and benign config strings. Must NOT be flagged.
 */
public class HardcodedSecretSafe {

    private static final String API_KEY = System.getenv("API_KEY");
    private static final String APP_NAME = "SentinelCore";
    private static final String VERSION = "1.0.0";
    private static final String DESCRIPTION = "A security scanning platform for enterprise use";
    private static final String DEFAULT_HOST = "localhost";
    private static final String PASSWORD_PLACEHOLDER = "changeme";
    private static final String SECRET_TEMPLATE = "${SECRET_VALUE}";

    public void configure() {
        String token = "test";
        String password = "xxx";
    }
}
