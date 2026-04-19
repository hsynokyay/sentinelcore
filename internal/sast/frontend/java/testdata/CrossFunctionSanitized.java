package com.example;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.PreparedStatement;

/**
 * INTER-PROCEDURAL NEGATIVE: taint flows from getParameter through a helper
 * that uses PreparedStatement (sanitizer). The engine must NOT flag this.
 */
public class CrossFunctionSanitized {

    public void handleRequest(HttpServletRequest request, Connection conn) throws Exception {
        String id = request.getParameter("id");
        safeQuery(conn, id);
    }

    private void safeQuery(Connection conn, String input) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, input);
        ps.executeQuery();
    }
}
