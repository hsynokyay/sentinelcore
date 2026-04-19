package bench.BenchSqliSafe001;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class BenchSqliSafe001 {
    public void handleRequest(HttpServletRequest request) throws Exception {
        String id = request.getParameter("id");
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test");
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        pstmt.setString(1, id);
        ResultSet rs = pstmt.executeQuery();
        while (rs.next()) {
            System.out.println(rs.getString(1));
        }
        rs.close();
        pstmt.close();
        conn.close();
    }
}
