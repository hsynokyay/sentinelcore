package com.example;

import javax.servlet.http.HttpServletResponse;

public class RedirectSafe {
    public void redirect(HttpServletResponse response) throws Exception {
        response.sendRedirect("/dashboard");
    }
}
