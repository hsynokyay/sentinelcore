package bench.BenchPath002;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class BenchPath002 {
    public void handleRequest(HttpServletRequest request) throws IOException {
        String userFile = request.getParameter("file");
        String fullPath = "/var/data/uploads/" + userFile;
        FileInputStream fis = new FileInputStream(fullPath);
        byte[] data = new byte[1024];
        fis.read(data);
        fis.close();
    }
}
