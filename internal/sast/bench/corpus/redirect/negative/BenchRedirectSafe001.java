package bench.redirect;

import javax.servlet.http.HttpServletResponse;

public class BenchRedirectSafe001 {
    public void redirect(HttpServletResponse response) throws Exception {
        response.sendRedirect("/dashboard");
    }
}
