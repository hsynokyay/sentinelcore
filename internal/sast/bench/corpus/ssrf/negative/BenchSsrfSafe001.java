package bench.ssrf;

import java.net.URL;

public class BenchSsrfSafe001 {
    public void fetch() throws Exception {
        URL url = new URL("https://api.internal.example.com/data");
        url.openStream();
    }
}
