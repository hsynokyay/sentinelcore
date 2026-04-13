package com.example;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.PreparedStatement;

/**
 * MIXED: two methods — one vulnerable, one safe. The engine must produce
 * exactly one finding (from the vulnerable method).
 */
public class SqlInjectionMixed {

    // VULNERABLE — should fire.
    public void vulnerableSearch(HttpServletRequest request, Connection conn) throws Exception {
        String name = request.getParameter("name");
        String sql = "SELECT * FROM products WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        stmt.executeQuery(sql);
    }

    // SAFE — should NOT fire.
    public void safeSearch(HttpServletRequest request, Connection conn) throws Exception {
        String name = request.getParameter("name");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM products WHERE name = ?");
        ps.setString(1, name);
        ps.executeQuery();
    }
}
