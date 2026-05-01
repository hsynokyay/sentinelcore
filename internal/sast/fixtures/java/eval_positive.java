// internal/sast/fixtures/java/eval_positive.java
import javax.script.*;
import javax.servlet.http.*;
import java.io.IOException;

public class EvalPositive extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
        try {
            Object out = engine.eval(req.getParameter("expr"));
            resp.getWriter().write(String.valueOf(out));
        } catch (ScriptException e) {
            resp.sendError(400);
        }
    }
}
