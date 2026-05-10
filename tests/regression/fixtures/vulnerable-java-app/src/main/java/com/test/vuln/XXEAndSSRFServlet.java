package com.test.vuln;

import javax.xml.parsers.*;
import javax.servlet.http.*;
import javax.servlet.ServletException;
import java.io.*;
import java.net.*;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

/**
 * CWE-611: XXE (XML External Entity)
 * CWE-918: SSRF
 * CWE-79: XSS
 * CWE-601: Open Redirect
 */
public class XXEAndSSRFServlet extends HttpServlet {

    // VULN: XXE - DocumentBuilderFactory without secure config
    public Document parseXml(String xmlContent) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new InputSource(new StringReader(xmlContent)));
    }

    // VULN: XXE - SAXParser
    public void parseSaxXml(InputStream stream) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser parser = factory.newSAXParser();
        parser.parse(stream, new org.xml.sax.helpers.DefaultHandler());
    }

    // VULN: XXE in XMLReader
    public void parseWithXmlReader(String xml) throws Exception {
        org.xml.sax.XMLReader reader = org.xml.sax.helpers.XMLReaderFactory.createXMLReader();
        reader.parse(new InputSource(new StringReader(xml)));
    }

    // VULN: SSRF - direct URL fetch
    public String fetchUrl(String urlString) throws IOException {
        URL url = new URL(urlString);
        URLConnection conn = url.openConnection();
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        return response.toString();
    }

    // VULN: SSRF via HttpURLConnection
    public String fetchWithHttp(String userUrl) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(userUrl).openConnection();
        conn.setRequestMethod("GET");
        InputStream is = conn.getInputStream();
        return new String(is.readAllBytes());
    }

    // VULN: SSRF using Apache HttpClient
    public String fetchWithApacheHttp(String url) throws IOException {
        org.apache.http.client.HttpClient client = org.apache.http.impl.client.HttpClientBuilder.create().build();
        org.apache.http.client.methods.HttpGet request = new org.apache.http.client.methods.HttpGet(url);
        org.apache.http.HttpResponse response = client.execute(request);
        return new String(response.getEntity().getContent().readAllBytes());
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        // VULN: Reflected XSS
        String name = req.getParameter("name");
        PrintWriter out = resp.getWriter();
        out.println("<html><body>");
        out.println("<h1>Hello, " + name + "!</h1>");
        out.println("<div>Search: " + req.getParameter("q") + "</div>");
        out.println("</body></html>");

        // VULN: Open Redirect
        String redirectUrl = req.getParameter("returnUrl");
        if (redirectUrl != null) {
            resp.sendRedirect(redirectUrl);
        }

        // VULN: Header injection / CRLF injection
        String userAgent = req.getParameter("ua");
        resp.setHeader("X-Custom-Header", userAgent);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        try {
            // VULN: XXE from request body
            String xml = req.getReader().lines().reduce("", (a, b) -> a + b);
            Document doc = parseXml(xml);

            // VULN: Stored XSS - writing input to response without encoding
            resp.getWriter().println("<div>" + xml + "</div>");
        } catch (Exception e) {
            // CWE-209: Stack trace exposure
            e.printStackTrace(resp.getWriter());
        }
    }
}
