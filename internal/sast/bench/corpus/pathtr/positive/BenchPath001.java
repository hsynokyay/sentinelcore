package bench.BenchPath001;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class BenchPath001 {
    public void handleRequest(HttpServletRequest request) throws IOException {
        String filename = request.getParameter("file");
        FileInputStream fis = new FileInputStream(filename);
        byte[] data = new byte[1024];
        fis.read(data);
        fis.close();
    }
}
