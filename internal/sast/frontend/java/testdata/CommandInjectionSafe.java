package com.example;

import javax.servlet.http.HttpServletRequest;
import java.util.Set;

/**
 * SAFE: user input is validated against an allowlist before exec.
 * Must NOT be flagged. The taint engine's conservative passthrough will
 * still propagate taint through the Set.contains check, so the engine
 * WILL flag this in the MVP (known limitation — allowlist validation is
 * not yet modeled as a sanitizer). This test documents the limitation.
 */
public class CommandInjectionSafe {
    private static final Set<String> ALLOWED = Set.of("ls", "whoami", "date");

    public void handleRequest(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        if (!ALLOWED.contains(cmd)) {
            throw new SecurityException("disallowed command");
        }
        Runtime.getRuntime().exec(cmd);
    }
}
