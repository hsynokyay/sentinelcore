package bench.BenchSqliSafe002;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.ResultSet;

public class BenchSqliSafe002 {
    public void listAllUsers() throws Exception {
        String sql = "SELECT * FROM users WHERE active = 1";
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        while (rs.next()) {
            System.out.println(rs.getString(1));
        }
        rs.close();
        stmt.close();
        conn.close();
    }
}
