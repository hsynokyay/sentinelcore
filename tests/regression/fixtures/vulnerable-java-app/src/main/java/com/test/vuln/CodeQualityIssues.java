package com.test.vuln;

import java.io.*;
import java.sql.*;
import java.util.*;
import java.util.concurrent.atomic.*;

/**
 * CWE-362: Race Condition
 * CWE-476: NULL Pointer Dereference
 * CWE-772: Missing Resource Release
 * CWE-190: Integer Overflow
 * CWE-369: Divide by Zero
 */
public class CodeQualityIssues {

    private int counter = 0;
    private List<String> sharedList = new ArrayList<>();

    // VULN: Race condition - non-atomic check-then-act
    public void incrementIfPositive() {
        if (counter >= 0) {
            counter++;
        }
    }

    // VULN: TOCTOU race condition
    public void readFileIfExists(String path) throws IOException {
        File f = new File(path);
        if (f.exists()) {
            // File could be deleted/replaced here
            FileInputStream fis = new FileInputStream(f);
            fis.read();
            fis.close();
        }
    }

    // VULN: Unsynchronized access to shared collection
    public void addItem(String item) {
        sharedList.add(item);
    }

    public String getItem(int index) {
        return sharedList.get(index);
    }

    // VULN: Resource leak - stream not closed
    public String readFile(String path) throws IOException {
        FileInputStream fis = new FileInputStream(path);
        byte[] data = fis.readAllBytes();
        return new String(data); // fis never closed
    }

    // VULN: Resource leak in DB connection
    public void runQuery(String sql) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test");
        Statement stmt = conn.createStatement();
        stmt.execute(sql);
        // Connection and statement never closed
    }

    // VULN: NPE - dereferencing potential null
    public int getLength(String s) {
        return s.length(); // s could be null
    }

    // VULN: Integer overflow
    public int multiply(int a, int b) {
        return a * b;
    }

    // VULN: Division by zero
    public int divide(int a, int b) {
        return a / b;
    }

    // VULN: Resource leak in exception path
    public void copyFile(String src, String dst) throws IOException {
        FileInputStream fis = new FileInputStream(src);
        FileOutputStream fos = new FileOutputStream(dst);
        byte[] buffer = new byte[1024];
        int len;
        while ((len = fis.read(buffer)) != -1) {
            fos.write(buffer, 0, len); // If this throws, streams leak
        }
        fis.close();
        fos.close();
    }

    // VULN: Empty catch swallowing exceptions
    public void doSomething() {
        try {
            riskyOperation();
        } catch (Exception e) {
            // Silent failure
        }
    }

    private void riskyOperation() throws Exception {}

    // VULN: System.exit in library code
    public void shutdown() {
        System.exit(0);
    }

    // VULN: Use of finalizer (deprecated)
    @Override
    protected void finalize() throws Throwable {
        super.finalize();
    }

    // VULN: Public mutable static field
    public static List<String> GLOBAL_CONFIG = new ArrayList<>();

    // VULN: Object passed by reference, mutable
    public List<String> getInternalList() {
        return sharedList; // Returns internal mutable state
    }

    // VULN: Equals without hashCode contract
    @Override
    public boolean equals(Object obj) {
        if (obj instanceof CodeQualityIssues) {
            return this.counter == ((CodeQualityIssues) obj).counter;
        }
        return false;
    }

    // VULN: Cloneable not implemented properly
    @Override
    public Object clone() throws CloneNotSupportedException {
        return super.clone(); // Shallow copy of mutable fields
    }
}
