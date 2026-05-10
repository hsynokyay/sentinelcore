package com.test.vuln;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javax.servlet.http.*;
import javax.servlet.ServletException;
import java.io.*;

/**
 * CWE-117: Log Injection
 * CWE-532: Insertion of Sensitive Information into Log
 * CWE-117: Log4Shell-style JNDI lookup
 */
public class LoggingVulnerabilities extends HttpServlet {

    private static final Logger logger = LogManager.getLogger(LoggingVulnerabilities.class);

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String userAgent = req.getHeader("User-Agent");
        String username = req.getParameter("user");
        String password = req.getParameter("password");

        // VULN: Log4Shell - logging untrusted user input directly (CVE-2021-44228)
        logger.info("User-Agent: " + userAgent);
        logger.warn("Login attempt for: " + username);
        logger.error("Request from: " + req.getHeader("X-Forwarded-For"));

        // VULN: Logging sensitive information
        logger.info("User " + username + " logged in with password " + password);
        logger.debug("Session token: " + req.getSession().getId());
        logger.info("Credit card: " + req.getParameter("cc"));
        logger.info("SSN provided: " + req.getParameter("ssn"));

        // VULN: Log Injection - CRLF in logs
        logger.info("Action performed: " + req.getParameter("action"));

        // CWE-209: Detailed errors to client
        try {
            int x = Integer.parseInt(req.getParameter("num"));
        } catch (Exception e) {
            resp.getWriter().println("Error details: " + e);
            e.printStackTrace(resp.getWriter());
        }
    }
}
