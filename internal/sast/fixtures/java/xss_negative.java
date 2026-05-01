// internal/sast/fixtures/java/xss_negative.java
import javax.servlet.http.*;
import java.io.*;
import org.owasp.encoder.Encode;

public class XssNegative extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        PrintWriter out = resp.getWriter();
        out.println("<h1>Hello " + Encode.forHtml(req.getParameter("name")) + "</h1>");
    }
}
