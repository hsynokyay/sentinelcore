package bench.ssrf;

import javax.servlet.http.HttpServletRequest;
import java.net.URL;

public class BenchSsrf001 {
    public void fetch(HttpServletRequest request) throws Exception {
        String input = request.getParameter("url");
        URL url = new URL(input);
        url.openStream();
    }
}
