// internal/sast/fixtures/java/header_positive.java
import javax.servlet.http.*;
import java.io.IOException;

public class HeaderPositive extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.addHeader("X-Tracking", req.getParameter("id"));
        resp.getWriter().write("ok");
    }
}
