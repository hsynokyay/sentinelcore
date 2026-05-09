import javax.servlet.http.*;
import java.io.IOException;

public class CookieNegative extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Cookie cookie = new Cookie("session", "abc123");
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setAttribute("SameSite", "Lax");
        resp.addCookie(cookie);
    }
}
