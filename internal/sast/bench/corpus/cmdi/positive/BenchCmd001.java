package bench.BenchCmd001;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class BenchCmd001 {
    public void handleRequest(HttpServletRequest request) throws IOException {
        String cmd = request.getParameter("cmd");
        Runtime rt = Runtime.getRuntime();
        rt.exec(cmd);
    }
}
