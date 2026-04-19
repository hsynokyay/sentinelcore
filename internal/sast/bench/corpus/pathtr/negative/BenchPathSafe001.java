package bench.BenchPathSafe001;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class BenchPathSafe001 {
    private static final String BASE_DIR = "/var/data/uploads";

    public void handleRequest(HttpServletRequest request) throws IOException {
        String userFile = request.getParameter("file");
        File base = new File(BASE_DIR);
        File resolved = new File(BASE_DIR, userFile);
        String canonicalPath = resolved.getCanonicalPath();
        if (!canonicalPath.startsWith(base.getCanonicalPath())) {
            throw new SecurityException("Path traversal detected");
        }
        FileInputStream fis = new FileInputStream(resolved);
        byte[] data = new byte[1024];
        fis.read(data);
        fis.close();
    }
}
