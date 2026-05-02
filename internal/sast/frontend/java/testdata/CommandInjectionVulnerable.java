package com.example;

import javax.servlet.http.HttpServletRequest;

/**
 * VULNERABLE: request.getParameter flows directly into Runtime.exec.
 * Must be flagged by SC-JAVA-CMD-001.
 */
public class CommandInjectionVulnerable {
    public void handleRequest(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        Runtime rt = Runtime.getRuntime();
        rt.exec(cmd);
    }
}
