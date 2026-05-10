package com.test.vuln;

/**
 * CWE-798: Use of Hardcoded Credentials
 * CWE-259: Hardcoded Password
 */
public class Secrets {

    // Database
    public static final String DB_PASSWORD = "P@ssw0rd123!";
    public static final String DB_ADMIN_PASS = "admin";
    public static final String DB_ROOT_PASSWORD = "toor";

    // AWS
    public static final String AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
    public static final String AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    public static final String AWS_S3_BUCKET_KEY = "AKIA1234567890ABCDEF";

    // API Keys
    public static final String STRIPE_API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
    public static final String GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    public static final String SLACK_TOKEN = "xoxb-1234-5678-abcdefghijklmnopqrstuvwx";
    public static final String GOOGLE_API_KEY = "AIzaSyD-1234567890abcdefghijklmnopqrstuv";

    // Encryption
    public static final String ENCRYPTION_KEY = "ThisIsMySecretKey1234567890!@#$%";
    public static final String JWT_SIGNING_KEY = "myJwtSecretKeyDoNotShare";
    public static final byte[] AES_KEY_BYTES = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
                                                  0x90, (byte)0xa0, (byte)0xb0, (byte)0xc0,
                                                  (byte)0xd0, (byte)0xe0, (byte)0xf0, 0x00};

    // Private keys
    public static final String PRIVATE_KEY_PEM =
        "-----BEGIN RSA PRIVATE KEY-----\n" +
        "MIIEpAIBAAKCAQEAwHJxKLU8fQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQ\n" +
        "AQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQAQ\n" +
        "-----END RSA PRIVATE KEY-----";

    // Database connection strings
    public static final String JDBC_URL = "jdbc:mysql://prod-db.internal.com:3306/users?user=admin&password=Pr0duct1on!";
    public static final String MONGO_URI = "mongodb://admin:supersecret@mongo.internal:27017/admin";

    // SMTP
    public static final String SMTP_PASSWORD = "EmailP@ss2024";
    public static final String SMTP_USER = "noreply@company.com";

    // OAuth
    public static final String OAUTH_CLIENT_SECRET = "abc123def456ghi789jkl012mno345pqr678stu";
    public static final String FACEBOOK_APP_SECRET = "1234567890abcdef1234567890abcdef";
}
