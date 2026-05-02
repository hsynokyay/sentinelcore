package bench.BenchSqli002;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.ResultSet;

public class BenchSqli002 {
    public void handleRequest(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        String sql = buildQuery(name);
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        rs.close();
        stmt.close();
        conn.close();
    }

    private String buildQuery(String userInput) {
        return "SELECT * FROM accounts WHERE name = '" + userInput + "'";
    }
}
