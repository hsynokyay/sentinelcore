import javax.servlet.http.*;
import java.io.IOException;

public class AuthheaderPositive extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setHeader("Authorization", req.getParameter("token"));
        resp.getWriter().write("ok");
    }
}
