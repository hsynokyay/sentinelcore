package com.test.vuln;

import java.io.*;
import javax.servlet.http.*;
import javax.servlet.ServletException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.thoughtworks.xstream.XStream;
import org.yaml.snakeyaml.Yaml;

/**
 * CWE-502: Deserialization of Untrusted Data
 */
public class DeserializationServlet extends HttpServlet {

    // VULN: Native Java deserialization of untrusted data
    public Object deserializeJava(byte[] data) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bais);
        return ois.readObject();
    }

    // VULN: Reading serialized object from HTTP request
    public Object readObjectFromRequest(HttpServletRequest req) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(req.getInputStream());
        return ois.readObject();
    }

    // VULN: Jackson polymorphic deserialization with default typing
    public Object deserializeJackson(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping(); // Dangerous!
        return mapper.readValue(json, Object.class);
    }

    // VULN: XStream deserialization
    public Object deserializeXStream(String xml) {
        XStream xstream = new XStream();
        return xstream.fromXML(xml);
    }

    // VULN: SnakeYAML unsafe load
    public Object deserializeYaml(String yaml) {
        Yaml y = new Yaml();
        return y.load(yaml);
    }

    // VULN: Reading objects from cookie
    public Object loadFromCookie(HttpServletRequest req) throws Exception {
        Cookie[] cookies = req.getCookies();
        for (Cookie c : cookies) {
            if ("session".equals(c.getName())) {
                byte[] data = java.util.Base64.getDecoder().decode(c.getValue());
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
                return ois.readObject();
            }
        }
        return null;
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        try {
            // VULN: Direct deserialization of HTTP body
            Object obj = readObjectFromRequest(req);
            resp.getWriter().println("Got: " + obj);
        } catch (Exception e) {
            throw new ServletException(e);
        }
    }
}
