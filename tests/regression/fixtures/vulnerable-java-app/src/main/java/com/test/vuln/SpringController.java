package com.test.vuln;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.expression.*;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import javax.servlet.http.*;
import java.io.*;
import java.lang.reflect.*;

/**
 * Spring-specific vulnerabilities
 * CWE-94: Code Injection
 * CWE-470: Unsafe Reflection
 */
@Controller
@RequestMapping("/api")
public class SpringController {

    // VULN: SpEL Injection (CVE-2022-22963 style)
    @GetMapping("/eval")
    @ResponseBody
    public String evaluateExpression(@RequestParam String expr) {
        ExpressionParser parser = new SpelExpressionParser();
        Expression expression = parser.parseExpression(expr);
        StandardEvaluationContext context = new StandardEvaluationContext();
        return expression.getValue(context).toString();
    }

    // VULN: Spring4Shell - direct object binding
    @PostMapping("/user")
    @ResponseBody
    public String createUser(@ModelAttribute UserBean user) {
        return "Created: " + user.getName();
    }

    // VULN: Server-Side Template Injection
    @GetMapping("/template")
    public String renderTemplate(@RequestParam String template, Model model) {
        return template; // User-controlled view name
    }

    // VULN: Unsafe reflection
    @PostMapping("/invoke")
    @ResponseBody
    public String invokeMethod(@RequestParam String className,
                                @RequestParam String methodName) throws Exception {
        Class<?> cls = Class.forName(className);
        Object obj = cls.getDeclaredConstructor().newInstance();
        Method method = cls.getMethod(methodName);
        return method.invoke(obj).toString();
    }

    // VULN: Class Loader manipulation
    @GetMapping("/loadClass")
    @ResponseBody
    public String loadClass(@RequestParam String name) throws Exception {
        Class<?> c = this.getClass().getClassLoader().loadClass(name);
        return c.getName();
    }

    // VULN: Groovy/JavaScript eval
    @PostMapping("/script")
    @ResponseBody
    public String runScript(@RequestParam String script) throws Exception {
        javax.script.ScriptEngine engine = new javax.script.ScriptEngineManager().getEngineByName("JavaScript");
        return String.valueOf(engine.eval(script));
    }

    // VULN: Open redirect
    @GetMapping("/redirect")
    public String redirect(@RequestParam String url) {
        return "redirect:" + url;
    }

    // VULN: Path traversal in static resource
    @GetMapping("/files/{name}")
    public void getFile(@PathVariable String name, HttpServletResponse resp) throws IOException {
        File f = new File("/var/files/" + name);
        java.nio.file.Files.copy(f.toPath(), resp.getOutputStream());
    }

    // Stub for Model
    interface Model { void addAttribute(String n, Object v); }

    public static class UserBean {
        private String name;
        private String role;
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getRole() { return role; }
        public void setRole(String role) { this.role = role; }
    }
}
