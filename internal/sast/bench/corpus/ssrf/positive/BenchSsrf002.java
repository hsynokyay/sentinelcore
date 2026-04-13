package bench.ssrf;

import javax.servlet.http.HttpServletRequest;
import org.apache.http.client.methods.HttpGet;

public class BenchSsrf002 {
    public void fetch(HttpServletRequest request) throws Exception {
        String input = request.getParameter("url");
        HttpGet httpGet = new HttpGet(input);
    }
}
