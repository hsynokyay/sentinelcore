package com.example;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileInputStream;

/**
 * VULNERABLE: request.getParameter flows into File constructor and then
 * FileInputStream. Must be flagged by SC-JAVA-PATH-001.
 */
public class PathTraversalVulnerable {
    public void handleRequest(HttpServletRequest request) throws Exception {
        String filename = request.getParameter("file");
        File f = new File(filename);
        FileInputStream fis = new FileInputStream(f);
        fis.close();
    }
}
