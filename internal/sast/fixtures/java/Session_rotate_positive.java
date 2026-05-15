import javax.servlet.http.*;

public class SessionRotatePositive extends HttpServlet {
    public void doPost(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
        try {
            req.login(req.getParameter("u"), req.getParameter("p"));  // SC-JAVA-SESSION-002
        } catch (javax.servlet.ServletException e) {
            resp.sendError(401);
        }
    }
}
