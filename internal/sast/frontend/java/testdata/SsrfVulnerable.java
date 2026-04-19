package com.example;

import javax.servlet.http.HttpServletRequest;
import java.net.URL;

public class SsrfVulnerable {
    public void fetch(HttpServletRequest request) throws Exception {
        String target = request.getParameter("url");
        URL url = new URL(target);
        url.openStream();
    }
}
