package com.example;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;

/**
 * CROSS-CLASS: taint flows from getParameter in this class into
 * SqlHelper.runQuery which contains the sink. The engine must detect this
 * when both files are analyzed together via AnalyzeAll.
 */
public class CrossClassSqli {

    public void handleRequest(HttpServletRequest request, Connection conn) throws Exception {
        String id = request.getParameter("id");
        String sql = "SELECT * FROM users WHERE id = " + id;
        SqlHelper helper = new SqlHelper();
        helper.runQuery(conn, sql);
    }
}
