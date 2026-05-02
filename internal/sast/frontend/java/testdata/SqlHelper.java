package com.example;

import java.sql.Connection;
import java.sql.Statement;

/**
 * Helper class called from CrossClassSqli. Contains the actual sink.
 */
public class SqlHelper {

    public void runQuery(Connection conn, String sql) throws Exception {
        Statement stmt = conn.createStatement();
        stmt.executeQuery(sql);
    }
}
