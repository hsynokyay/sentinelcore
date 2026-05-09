// internal/sast/fixtures/java/ssti_negative.java
import javax.servlet.http.*;
import java.io.*;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.VelocityContext;

public class SstiNegative extends HttpServlet {
    private static final String TEMPLATE = "Hello $name";
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        VelocityEngine engine = new VelocityEngine();
        VelocityContext ctx = new VelocityContext();
        ctx.put("name", req.getParameter("name"));
        StringWriter out = new StringWriter();
        engine.evaluate(ctx, out, "user", TEMPLATE);
        resp.getWriter().write(out.toString());
    }
}
