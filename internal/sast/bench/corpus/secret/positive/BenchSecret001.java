package bench.BenchSecret001;

import java.net.HttpURLConnection;
import java.net.URL;

public class BenchSecret001 {
    private static final String API_KEY = "sk-live-abcdef1234567890xyz";

    public void callExternalService() throws Exception {
        URL url = new URL("https://api.example.com/data");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestProperty("Authorization", "Bearer " + API_KEY);
        conn.getInputStream();
        conn.disconnect();
    }
}
