package bench.BenchSecretSafe001;

import java.sql.Connection;
import java.sql.DriverManager;

public class BenchSecretSafe001 {
    private static final String PASSWORD = "changeme";

    public Connection getConnection() throws Exception {
        return DriverManager.getConnection(
            "jdbc:h2:mem:test",
            "sa",
            PASSWORD
        );
    }
}
