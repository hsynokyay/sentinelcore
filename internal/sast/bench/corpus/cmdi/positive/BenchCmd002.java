package bench.BenchCmd002;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class BenchCmd002 {
    public void handleRequest(HttpServletRequest request) throws IOException {
        String host = request.getParameter("host");
        String command = "ping -c 3 " + host;
        Runtime rt = Runtime.getRuntime();
        rt.exec(command);
    }
}
