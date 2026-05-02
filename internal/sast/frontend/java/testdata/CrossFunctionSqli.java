package com.example;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.Statement;

/**
 * INTER-PROCEDURAL: taint flows from getParameter through a helper method
 * into executeQuery. The taint engine must follow the flow across the call
 * boundary.
 *
 * Flow: handleRequest → buildQuery → executeQuery (sink)
 */
public class CrossFunctionSqli {

    public void handleRequest(HttpServletRequest request, Connection conn) throws Exception {
        String id = request.getParameter("id");
        String sql = buildQuery(id);
        Statement stmt = conn.createStatement();
        stmt.executeQuery(sql);
    }

    private String buildQuery(String input) {
        return "SELECT * FROM users WHERE id = " + input;
    }
}
