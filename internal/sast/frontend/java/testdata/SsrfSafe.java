package com.example;

import java.net.URL;

public class SsrfSafe {
    public void fetch() throws Exception {
        URL url = new URL("https://api.internal.example.com/data");
        url.openStream();
    }
}
