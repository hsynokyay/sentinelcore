// internal/sast/fixtures/java/ssti_positive.java
import javax.servlet.http.*;
import java.io.*;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.VelocityContext;

public class SstiPositive extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String template = "Hello $name " + req.getParameter("suffix");
        VelocityEngine engine = new VelocityEngine();
        StringWriter out = new StringWriter();
        engine.evaluate(new VelocityContext(), out, "user", template);
        resp.getWriter().write(out.toString());
    }
}
