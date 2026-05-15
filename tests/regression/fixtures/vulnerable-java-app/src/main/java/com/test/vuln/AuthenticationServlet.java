package com.test.vuln;

import javax.servlet.http.*;
import javax.servlet.ServletException;
import java.io.*;
import io.jsonwebtoken.*;
import java.util.Date;

/**
 * CWE-287: Improper Authentication
 * CWE-384: Session Fixation
 * CWE-352: CSRF
 * CWE-639: IDOR
 * CWE-862: Missing Authorization
 */
public class AuthenticationServlet extends HttpServlet {

    private static final String JWT_SECRET = "secret";

    // VULN: JWT with 'none' algorithm accepted
    public Claims parseJwtUnsafe(String token) {
        return Jwts.parser().parseClaimsJwt(token).getBody();
    }

    // VULN: JWT secret hardcoded and weak
    public String createJwt(String username) {
        return Jwts.builder()
            .setSubject(username)
            .setExpiration(new Date(System.currentTimeMillis() + 86400000))
            .signWith(SignatureAlgorithm.HS256, JWT_SECRET)
            .compact();
    }

    // VULN: Authentication bypass via parameter
    public boolean isAuthenticated(HttpServletRequest req) {
        String adminParam = req.getParameter("admin");
        if ("true".equals(adminParam)) {
            return true;
        }
        return req.getSession().getAttribute("user") != null;
    }

    // VULN: Session Fixation - not regenerating session ID after login
    public void login(HttpServletRequest req, String username) {
        HttpSession session = req.getSession(true);
        session.setAttribute("user", username);
        // Session ID never regenerated after authentication
    }

    // VULN: IDOR - no authorization check
    public void getUserDocument(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String docId = req.getParameter("docId");
        File doc = new File("/documents/" + docId);
        FileInputStream fis = new FileInputStream(doc);
        resp.getOutputStream().write(fis.readAllBytes());
    }

    // VULN: Mass Assignment
    public void updateUserProfile(HttpServletRequest req) {
        String username = req.getParameter("username");
        String email = req.getParameter("email");
        String role = req.getParameter("role"); // Should not be user-controllable!
        String isAdmin = req.getParameter("isAdmin"); // Should not be user-controllable!

        // Update everything blindly...
        UserProfile profile = new UserProfile();
        profile.setUsername(username);
        profile.setEmail(email);
        profile.setRole(role);
        profile.setAdmin(Boolean.parseBoolean(isAdmin));
    }

    // VULN: Missing CSRF protection
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        // No CSRF token validation
        String action = req.getParameter("action");
        if ("transfer".equals(action)) {
            String amount = req.getParameter("amount");
            String to = req.getParameter("to");
            transferMoney(req.getSession().getAttribute("user").toString(), to, amount);
        } else if ("delete".equals(action)) {
            String id = req.getParameter("id");
            deleteAccount(id);
        }
    }

    private void transferMoney(String from, String to, String amount) {}
    private void deleteAccount(String id) {}

    // VULN: Insecure cookie - no Secure/HttpOnly flags
    public void setSessionCookie(HttpServletResponse resp, String value) {
        Cookie cookie = new Cookie("session", value);
        cookie.setMaxAge(86400);
        // Missing: cookie.setSecure(true)
        // Missing: cookie.setHttpOnly(true)
        resp.addCookie(cookie);
    }

    // VULN: Plaintext password storage
    public void storePassword(String username, String password) {
        try {
            FileWriter fw = new FileWriter("/etc/passwords.txt", true);
            fw.write(username + ":" + password + "\n");
            fw.close();
        } catch (IOException e) {}
    }

    // VULN: Timing attack on string comparison
    public boolean verifyApiKey(String provided, String stored) {
        return provided.equals(stored);
    }

    // VULN: LDAP Injection
    public boolean ldapAuth(String username, String password) throws Exception {
        java.util.Hashtable<String, String> env = new java.util.Hashtable<>();
        env.put(javax.naming.Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(javax.naming.Context.PROVIDER_URL, "ldap://localhost:389");

        javax.naming.directory.DirContext ctx = new javax.naming.directory.InitialDirContext(env);
        String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";
        javax.naming.NamingEnumeration<?> results = ctx.search("dc=example,dc=com", filter, null);
        return results.hasMore();
    }

    static class UserProfile {
        String username, email, role;
        boolean admin;
        public void setUsername(String u) { this.username = u; }
        public void setEmail(String e) { this.email = e; }
        public void setRole(String r) { this.role = r; }
        public void setAdmin(boolean a) { this.admin = a; }
    }
}
