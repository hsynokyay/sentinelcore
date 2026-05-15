package com.test.vuln;

import java.sql.*;
import javax.servlet.http.*;
import javax.servlet.ServletException;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * CWE-89: SQL Injection vulnerabilities
 */
public class SQLInjectionServlet extends HttpServlet {

    private static final String DB_URL = "jdbc:mysql://localhost:3306/testdb";
    private static final String DB_USER = "root";
    // CWE-798: Hardcoded credentials
    private static final String DB_PASSWORD = "admin123";

    // VULN: Classic SQL Injection via string concatenation
    public User getUserById(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        ResultSet rs = stmt.executeQuery(query);
        if (rs.next()) {
            return new User(rs.getString("username"), rs.getString("email"));
        }
        return null;
    }

    // VULN: SQL Injection in login
    public boolean login(String username, String password) throws SQLException {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
        ResultSet rs = stmt.executeQuery(sql);
        return rs.next();
    }

    // VULN: SQL Injection via String.format
    public void deleteRecord(String id) throws SQLException {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        Statement stmt = conn.createStatement();
        String query = String.format("DELETE FROM records WHERE id = %s", id);
        stmt.executeUpdate(query);
    }

    // VULN: PreparedStatement misused (still concatenating)
    public void updateUser(String userId, String email) throws SQLException {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        String sql = "UPDATE users SET email = '" + email + "' WHERE id = " + userId;
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.executeUpdate();
    }

    // VULN: Second-order SQL injection
    public void searchProducts(String category) throws SQLException {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        StringBuilder sb = new StringBuilder("SELECT * FROM products WHERE category LIKE '%");
        sb.append(category);
        sb.append("%'");
        Statement stmt = conn.createStatement();
        stmt.executeQuery(sb.toString());
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        // VULN: Direct user input to SQL
        String id = req.getParameter("id");
        try {
            User user = getUserById(id);
            PrintWriter out = resp.getWriter();
            // VULN: XSS - reflected
            out.println("<html><body>User: " + id + "</body></html>");
        } catch (SQLException e) {
            // CWE-209: Information exposure through error message
            resp.getWriter().println("DB Error: " + e.getMessage() + " Stack: " + e.getStackTrace()[0]);
        }
    }

    static class User {
        String username, email;
        User(String u, String e) { username = u; email = e; }
    }
}
