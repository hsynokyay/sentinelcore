package bench.BenchSqli001;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.ResultSet;

public class BenchSqli001 {
    public void handleRequest(HttpServletRequest request) throws Exception {
        String id = request.getParameter("id");
        String sql = "SELECT * FROM users WHERE id = '" + id + "'";
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
