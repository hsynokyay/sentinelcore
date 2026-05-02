import javax.servlet.http.*;
import java.io.IOException;

public class AuthheaderNegative extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setHeader("Authorization", "Bearer " + System.getenv("SERVICE_TOKEN"));
        resp.getWriter().write("ok");
    }
}
