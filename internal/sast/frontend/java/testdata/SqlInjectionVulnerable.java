package com.example;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.Statement;

/**
 * VULNERABLE: request.getParameter flows into string concat and then into
 * Statement.executeQuery without PreparedStatement parameterization.
 *
 * The taint engine must flag this with SC-JAVA-SQL-001 at the executeQuery
 * call on line 17.
 */
public class SqlInjectionVulnerable {
    public void handleRequest(HttpServletRequest request, Connection conn) throws Exception {
        String id = request.getParameter("id");
        String sql = "SELECT * FROM users WHERE id = " + id;
        Statement stmt = conn.createStatement();
        stmt.executeQuery(sql);
    }
}
