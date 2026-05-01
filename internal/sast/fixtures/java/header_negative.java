// internal/sast/fixtures/java/header_negative.java
import javax.servlet.http.*;
import java.io.IOException;

public class HeaderNegative extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String raw = req.getParameter("id");
        String safe = (raw == null) ? "" : raw.replaceAll("[\\r\\n]", "");
        resp.addHeader("X-Tracking", safe);
        resp.getWriter().write("ok");
    }
}
