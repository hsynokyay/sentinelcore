package bench.BenchCmdSafe001;

import java.io.IOException;

public class BenchCmdSafe001 {
    public void checkDiskUsage() throws IOException {
        String command = "df -h /var/log";
        Runtime rt = Runtime.getRuntime();
        rt.exec(command);
    }
}
