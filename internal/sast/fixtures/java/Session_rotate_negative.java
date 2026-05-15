import javax.servlet.http.*;

public class SessionRotateNegative extends HttpServlet {
    public void doPost(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
        try {
            req.login(req.getParameter("u"), req.getParameter("p"));
            req.changeSessionId();
        } catch (javax.servlet.ServletException e) {
            resp.sendError(401);
        }
    }
}
