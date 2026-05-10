<%@ page language="java" contentType="text/html; charset=UTF-8" %>
<%@ page import="java.sql.*, java.io.*" %>
<%
    // VULN: XSS via JSP scriptlet
    String name = request.getParameter("name");
    String search = request.getParameter("q");
%>
<html>
<head><title>Vulnerable JSP</title></head>
<body>
    <!-- VULN: Reflected XSS -->
    <h1>Welcome, <%= name %></h1>
    <p>Your search: <%= search %></p>

    <%
        // VULN: SQL injection in JSP
        String userId = request.getParameter("id");
        String query = "SELECT * FROM users WHERE id = " + userId;

        Class.forName("com.mysql.jdbc.Driver");
        // VULN: Hardcoded credentials in JSP
        Connection conn = DriverManager.getConnection(
            "jdbc:mysql://localhost/db", "root", "password123");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);

        while (rs.next()) {
            // VULN: XSS from DB output
            out.println("<div>" + rs.getString("username") + "</div>");
        }

        // VULN: Command injection in JSP
        String host = request.getParameter("host");
        if (host != null) {
            Process p = Runtime.getRuntime().exec("ping " + host);
        }

        // VULN: Path traversal in include
        String page = request.getParameter("page");
    %>

    <!-- VULN: Dynamic include with user input -->
    <jsp:include page="<%= page %>" />

    <!-- VULN: Open redirect -->
    <%
        String returnUrl = request.getParameter("returnUrl");
        if (returnUrl != null) {
            response.sendRedirect(returnUrl);
        }
    %>
</body>
</html>
