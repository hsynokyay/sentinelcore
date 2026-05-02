// internal/sast/fixtures/java/xss_positive.java
import javax.servlet.http.*;
import java.io.*;

public class XssPositive extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        PrintWriter out = resp.getWriter();
        out.println("<h1>Hello " + req.getParameter("name") + "</h1>");
    }
}
