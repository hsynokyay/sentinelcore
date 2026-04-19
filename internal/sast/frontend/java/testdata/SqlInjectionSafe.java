package com.example;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.PreparedStatement;

/**
 * SAFE: request.getParameter flows into a PreparedStatement with setString.
 * The taint engine must NOT flag this file.
 */
public class SqlInjectionSafe {
    public void handleRequest(HttpServletRequest request, Connection conn) throws Exception {
        String id = request.getParameter("id");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, id);
        ps.executeQuery();
    }
}
