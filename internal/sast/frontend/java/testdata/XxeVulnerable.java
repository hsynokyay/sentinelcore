package com.example;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.InputStream;

public class XxeVulnerable {
    public Document parseXml(InputStream input) throws Exception {
        // VULNERABLE: no setFeature() to disable external entities
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(input);
    }
}
