package bench.BenchSqli003;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.ResultSet;

public class BenchSqli003 {
    public void handleRequest(HttpServletRequest request) throws Exception {
        String token = request.getHeader("X-Auth-Token");
        String sql = "SELECT * FROM sessions WHERE token = '" + token + "'";
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        rs.close();
        stmt.close();
        conn.close();
    }
}
