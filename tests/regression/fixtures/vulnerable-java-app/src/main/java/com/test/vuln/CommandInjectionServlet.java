package com.test.vuln;

import java.io.*;
import javax.servlet.http.*;
import javax.servlet.ServletException;

/**
 * CWE-78: OS Command Injection
 * CWE-22: Path Traversal
 * CWE-434: Unrestricted Upload
 */
public class CommandInjectionServlet extends HttpServlet {

    // VULN: Command Injection via Runtime.exec
    public String pingHost(String host) throws IOException {
        Process p = Runtime.getRuntime().exec("ping -c 4 " + host);
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }

    // VULN: Command injection via shell
    public void executeShellCommand(String userInput) throws IOException {
        String[] cmd = { "/bin/sh", "-c", "echo " + userInput };
        Runtime.getRuntime().exec(cmd);
    }

    // VULN: Command injection via ProcessBuilder
    public void runScript(String filename) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("bash", "-c", "cat " + filename);
        pb.start();
    }

    // VULN: Path Traversal
    public String readFile(String filename) throws IOException {
        File file = new File("/var/data/" + filename);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\n");
        }
        reader.close();
        return content.toString();
    }

    // VULN: Path Traversal in download
    public void downloadFile(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String filename = req.getParameter("file");
        File file = new File("/uploads/" + filename);
        FileInputStream fis = new FileInputStream(file);
        OutputStream os = resp.getOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = fis.read(buffer)) != -1) {
            os.write(buffer, 0, len);
        }
        fis.close();
    }

    // VULN: Zip Slip vulnerability
    public void extractZip(java.util.zip.ZipInputStream zis, String destDir) throws IOException {
        java.util.zip.ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            File outFile = new File(destDir, entry.getName());
            FileOutputStream fos = new FileOutputStream(outFile);
            byte[] buffer = new byte[1024];
            int len;
            while ((len = zis.read(buffer)) > 0) {
                fos.write(buffer, 0, len);
            }
            fos.close();
        }
    }

    // VULN: Unrestricted File Upload
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String filename = req.getParameter("filename");
        InputStream input = req.getInputStream();
        File uploadFile = new File("/var/www/uploads/" + filename);
        FileOutputStream fos = new FileOutputStream(uploadFile);
        byte[] buffer = new byte[4096];
        int read;
        while ((read = input.read(buffer)) != -1) {
            fos.write(buffer, 0, read);
        }
        fos.close();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String host = req.getParameter("host");
        String result = pingHost(host);
        resp.getWriter().println(result);
    }
}
