# Vulnerable Java Application - SAST Test Suite

**WARNING:** This application is INTENTIONALLY VULNERABLE for testing SAST tools.
DO NOT deploy in any real environment.

## Purpose

Test corpus for Static Application Security Testing (SAST) tools to validate
detection of common Java vulnerabilities mapped to OWASP Top 10 and CWE Top 25.

## Vulnerability Coverage

### Injection (OWASP A03)
| File | CWE | Description |
|------|-----|-------------|
| SQLInjectionServlet.java | CWE-89 | SQL Injection (concat, String.format, misused PreparedStatement) |
| CommandInjectionServlet.java | CWE-78 | OS Command Injection (Runtime.exec, ProcessBuilder) |
| XXEAndSSRFServlet.java | CWE-611 | XXE in DocumentBuilder, SAXParser, XMLReader |
| AuthenticationServlet.java | CWE-90 | LDAP Injection |
| LoggingVulnerabilities.java | CWE-117 | Log Injection / Log4Shell |
| SpringController.java | CWE-94 | SpEL Injection, Script Engine eval |
| index.jsp | CWE-79, CWE-89 | XSS and SQLi in JSP |

### Broken Access Control (OWASP A01)
| File | CWE | Description |
|------|-----|-------------|
| AuthenticationServlet.java | CWE-639 | IDOR |
| AuthenticationServlet.java | CWE-862 | Missing Authorization |
| AuthenticationServlet.java | CWE-352 | Missing CSRF |
| CommandInjectionServlet.java | CWE-22 | Path Traversal |
| CommandInjectionServlet.java | CWE-23 | Zip Slip |

### Cryptographic Failures (OWASP A02)
| File | CWE | Description |
|------|-----|-------------|
| CryptoVulnerabilities.java | CWE-327 | MD5, SHA1, DES, RC4, Blowfish |
| CryptoVulnerabilities.java | CWE-326 | AES-ECB, static IV, 512-bit RSA |
| CryptoVulnerabilities.java | CWE-330 | Random instead of SecureRandom |
| CryptoVulnerabilities.java | CWE-759 | Unsalted password hashing |
| CryptoVulnerabilities.java | CWE-295 | Disabled SSL verification |

### Hardcoded Secrets (CWE-798)
| File | Description |
|------|-------------|
| Secrets.java | AWS keys, Stripe, GitHub, RSA private key |
| application.properties | DB password, OAuth secret, JWT secret |

### Insecure Deserialization (OWASP A08)
| File | CWE | Description |
|------|-----|-------------|
| DeserializationServlet.java | CWE-502 | Java native, Jackson default typing, XStream, SnakeYAML |

### SSRF (OWASP A10)
| File | CWE | Description |
|------|-----|-------------|
| XXEAndSSRFServlet.java | CWE-918 | URL.openConnection, HttpURLConnection, Apache HttpClient |

### XSS (CWE-79)
| File | Description |
|------|-------------|
| SQLInjectionServlet.java | Reflected XSS in PrintWriter |
| XXEAndSSRFServlet.java | Reflected and stored XSS |
| index.jsp | XSS in JSP scriptlet |

### Authentication Failures (OWASP A07)
| File | CWE | Description |
|------|-----|-------------|
| AuthenticationServlet.java | CWE-287 | Auth bypass via parameter |
| AuthenticationServlet.java | CWE-384 | Session fixation |
| AuthenticationServlet.java | CWE-256 | Plaintext password storage |
| AuthenticationServlet.java | CWE-208 | Timing attack |
| AuthenticationServlet.java | CWE-915 | Mass assignment |

### Vulnerable Components (OWASP A06)
pom.xml includes:
- Log4j 2.14.1 (Log4Shell - CVE-2021-44228)
- Struts 2.3.32 (CVE-2017-5638)
- Spring 5.3.17 (Spring4Shell - CVE-2022-22965)
- Jackson 2.9.8 (CVE-2019-12384)
- Commons Collections 3.2.1 (CVE-2015-6420)
- SnakeYAML 1.29 (CVE-2022-1471)
- XStream 1.4.17 (CVE-2021-39139)
- dom4j 1.6.1 (CVE-2020-10683)
- MySQL Connector 5.1.46
- Bouncy Castle 1.55
- Apache Commons FileUpload 1.3.2 (CVE-2016-1000031)

### Security Misconfiguration (OWASP A05)
| File | Description |
|------|-------------|
| web.xml | Long session timeout, no HttpOnly/Secure cookies, URL tracking |
| application.properties | debug=true, trust.all.certs=true |
| AuthenticationServlet.java | Insecure cookie config |

### Information Disclosure (CWE-209)
- Stack traces written to response
- Exception messages in HTTP responses
- Sensitive data (passwords, SSN, CC) logged

### Code Quality / SEI CERT
| File | Description |
|------|-------------|
| CodeQualityIssues.java | Race conditions, NPE, resource leaks, integer overflow, divide-by-zero, swallowed exceptions, exposed internal mutable state |

## Build

```bash
mvn clean package
```

Output: `target/vulnerable-app.war`

## Expected Findings

A solid SAST tool should detect roughly 100+ findings across categories.
SCA portion should flag ~15 vulnerable dependencies.

## Test Commands

```bash
# Just compile, don't run
mvn compile

# Package as WAR
mvn package -DskipTests
```
