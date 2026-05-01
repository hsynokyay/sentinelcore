// internal/sast/fixtures/java/eval_negative.java
import javax.servlet.http.*;
import java.io.IOException;

public class EvalNegative extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String expr = req.getParameter("expr");
        if (!expr.matches("\\d+(\\s*[+\\-*/]\\s*\\d+)*")) {
            resp.sendError(400);
            return;
        }
        // Hand-rolled tiny calculator parses tokens manually
        resp.getWriter().write(SafeCalc.evaluate(expr));
    }
}
