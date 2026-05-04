import javax.servlet.http.*;
import java.io.IOException;

public class CookiePositive extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Cookie cookie = new Cookie("session", "abc123");
        resp.addCookie(cookie);
    }
}
