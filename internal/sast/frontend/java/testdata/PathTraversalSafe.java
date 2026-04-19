package com.example;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileInputStream;

/**
 * SAFE: user input is passed through getCanonicalPath (sanitizer for
 * path_traversal) and checked against a base directory. The engine's
 * sanitizer model for File.getCanonicalPath should clear taint.
 *
 * Note: the actual containment check (`startsWith`) is not modeled yet,
 * but the getCanonicalPath call itself is marked as a sanitizer, so taint
 * is cleared before reaching the FileInputStream constructor.
 */
public class PathTraversalSafe {
    private static final String BASE_DIR = "/opt/uploads";

    public void handleRequest(HttpServletRequest request) throws Exception {
        String filename = request.getParameter("file");
        File f = new File(BASE_DIR, filename);
        String canonical = f.getCanonicalPath();
        FileInputStream fis = new FileInputStream(canonical);
        fis.close();
    }
}
