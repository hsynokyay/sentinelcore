package bench.BenchSecret002;

import java.sql.Connection;
import java.sql.DriverManager;

public class BenchSecret002 {
    private static final String DB_PASSWORD = "ProductionP@ssw0rd2024!";

    public Connection getConnection() throws Exception {
        return DriverManager.getConnection(
            "jdbc:postgresql://db.internal:5432/app",
            "admin",
            DB_PASSWORD
        );
    }
}
