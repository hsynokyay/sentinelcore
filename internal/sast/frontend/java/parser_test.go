package java

import (
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
)

// TestParseProducesClassAndMethod verifies the parser extracts the top-level
// class, its method, and the IR call instruction for Cipher.getInstance.
func TestParseProducesClassAndMethod(t *testing.T) {
	src := []byte(`package com.example;
import javax.crypto.Cipher;
public class Foo {
    void bad() throws Exception {
        Cipher c = Cipher.getInstance("DES");
    }
}`)
	mod := Parse("Foo.java", src)

	if mod.Package != "com.example" {
		t.Errorf("package: got %q", mod.Package)
	}
	if len(mod.Classes) != 1 {
		t.Fatalf("classes: got %d", len(mod.Classes))
	}
	cls := mod.Classes[0]
	if cls.Name != "Foo" || cls.FQN != "com.example.Foo" {
		t.Errorf("class: got name=%q fqn=%q", cls.Name, cls.FQN)
	}
	if len(cls.Methods) != 1 {
		t.Fatalf("methods: got %d", len(cls.Methods))
	}
	fn := cls.Methods[0]
	if fn.Name != "bad" || fn.FQN != "com.example.Foo.bad" {
		t.Errorf("method: got name=%q fqn=%q", fn.Name, fn.FQN)
	}
	if len(fn.Blocks) != 1 {
		t.Fatalf("blocks: got %d", len(fn.Blocks))
	}

	// Verify the parser emitted a call to Cipher.getInstance resolved via
	// the 'import javax.crypto.Cipher;' declaration.
	var call *ir.Instruction
	for _, inst := range fn.Blocks[0].Instructions {
		if inst.Op == ir.OpCall && inst.Callee == "getInstance" {
			call = inst
			break
		}
	}
	if call == nil {
		t.Fatalf("did not find Cipher.getInstance call in block: %+v", fn.Blocks[0].Instructions)
	}
	if call.ReceiverType != "javax.crypto.Cipher" {
		t.Errorf("receiver type: got %q, want javax.crypto.Cipher", call.ReceiverType)
	}
	if call.CalleeFQN != "javax.crypto.Cipher.getInstance" {
		t.Errorf("callee fqn: got %q", call.CalleeFQN)
	}
	if len(call.Operands) != 1 || call.Operands[0].Kind != ir.OperandConstString || call.Operands[0].StrVal != "DES" {
		t.Errorf("first operand: %+v", call.Operands)
	}
	if call.Loc.Line != 5 {
		t.Errorf("line: got %d, want 5", call.Loc.Line)
	}
}

// TestControlFlowKeywordsAreNotCalls verifies the parser correctly excludes
// if/for/while/switch/synchronized/catch/return/throw/new from the call
// detector. A single class with one method that uses many of these keywords
// should produce exactly one call (the method body's real invocation).
func TestControlFlowKeywordsAreNotCalls(t *testing.T) {
	src := []byte(`package com.example;
public class Foo {
    void m(int n) {
        if (n > 0) {
            for (int i = 0; i < n; i++) {
                while (i < 10) {
                    synchronized (this) {
                        try {
                            System.out.println("x");
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }
                    break;
                }
            }
        }
    }
}`)
	mod := Parse("Foo.java", src)
	if len(mod.Classes) != 1 {
		t.Fatalf("classes: got %d", len(mod.Classes))
	}
	calls := collectCalls(mod)

	// Expected real calls:
	//   System.out.println("x")   -> callee "println"
	//   new RuntimeException(e)   -> emitted as a call with callee
	//                                 "RuntimeException" and receiver "" because
	//                                 our walker sees the IDENT followed by '('.
	// Every other `if (`, `for (`, `while (`, `catch (`, `synchronized (`,
	// and `throw new` pattern must NOT produce a call.
	for _, c := range calls {
		if c.Callee == "if" || c.Callee == "for" || c.Callee == "while" ||
			c.Callee == "synchronized" || c.Callee == "catch" ||
			c.Callee == "return" || c.Callee == "throw" {
			t.Errorf("keyword leaked into calls: %+v", c)
		}
	}
	// At least println should be there.
	foundPrintln := false
	for _, c := range calls {
		if c.Callee == "println" {
			foundPrintln = true
		}
	}
	if !foundPrintln {
		t.Errorf("expected println call, got %+v", calls)
	}
}

// TestImportResolution verifies the parser resolves simple class names back
// to their fully-qualified import names when a matching import exists.
func TestImportResolution(t *testing.T) {
	src := []byte(`package com.example;
import java.security.MessageDigest;
import javax.crypto.Cipher;
public class Foo {
    void m() throws Exception {
        MessageDigest.getInstance("MD5");
        Cipher.getInstance("DES");
        Unknown.method("x");
    }
}`)
	mod := Parse("Foo.java", src)
	calls := collectCalls(mod)
	if len(calls) != 3 {
		t.Fatalf("expected 3 calls, got %d", len(calls))
	}
	byCallee := map[string]*ir.Instruction{}
	for _, c := range calls {
		byCallee[c.Callee] = c
	}
	if byCallee["getInstance"] == nil {
		// One of the two getInstance calls will collide; check them both.
	}
	// Expect MessageDigest.getInstance resolved.
	foundMD := false
	foundCipher := false
	foundUnknown := false
	for _, c := range calls {
		if c.Callee == "getInstance" && c.ReceiverType == "java.security.MessageDigest" {
			foundMD = true
		}
		if c.Callee == "getInstance" && c.ReceiverType == "javax.crypto.Cipher" {
			foundCipher = true
		}
		if c.Callee == "method" && c.ReceiverType == "Unknown" {
			foundUnknown = true
		}
	}
	if !foundMD {
		t.Errorf("MessageDigest.getInstance not resolved")
	}
	if !foundCipher {
		t.Errorf("Cipher.getInstance not resolved")
	}
	if !foundUnknown {
		t.Errorf("Unknown.method not recorded as bare receiver")
	}
}

// TestNestedClasses verifies that a nested class is emitted as a separate
// Class with a dotted FQN, and its methods are attached to the nested class.
func TestNestedClasses(t *testing.T) {
	src := []byte(`package com.example;
public class Outer {
    void outerMethod() {
        System.out.println("a");
    }
    public static class Inner {
        void innerMethod() {
            System.out.println("b");
        }
    }
}`)
	mod := Parse("Outer.java", src)
	if len(mod.Classes) != 2 {
		t.Fatalf("classes: got %d, want 2", len(mod.Classes))
	}
	// Both classes are appended to Module.Classes, flattened.
	byFQN := map[string]*ir.Class{}
	for _, c := range mod.Classes {
		byFQN[c.FQN] = c
	}
	if byFQN["com.example.Outer"] == nil {
		t.Errorf("outer class missing")
	}
	if byFQN["com.example.Outer.Inner"] == nil {
		t.Errorf("nested class missing")
	}
	// Verify outerMethod is on Outer, innerMethod is on Inner.
	if len(byFQN["com.example.Outer"].Methods) != 1 || byFQN["com.example.Outer"].Methods[0].Name != "outerMethod" {
		t.Errorf("outer methods: %+v", byFQN["com.example.Outer"].Methods)
	}
	if len(byFQN["com.example.Outer.Inner"].Methods) != 1 || byFQN["com.example.Outer.Inner"].Methods[0].Name != "innerMethod" {
		t.Errorf("inner methods: %+v", byFQN["com.example.Outer.Inner"].Methods)
	}
}

// TestAnnotationsAreSkipped verifies the parser doesn't mistake annotations
// for method declarations, and doesn't emit annotation applications as calls.
func TestAnnotationsAreSkipped(t *testing.T) {
	src := []byte(`package com.example;
import org.springframework.web.bind.annotation.RequestMapping;
public class Controller {
    @RequestMapping("/foo")
    public void handle() {
        System.out.println("ok");
    }
}`)
	mod := Parse("Controller.java", src)
	if len(mod.Classes) != 1 {
		t.Fatalf("classes: got %d", len(mod.Classes))
	}
	if len(mod.Classes[0].Methods) != 1 || mod.Classes[0].Methods[0].Name != "handle" {
		t.Errorf("methods: %+v", mod.Classes[0].Methods)
	}
	calls := collectCalls(mod)
	for _, c := range calls {
		if c.Callee == "RequestMapping" {
			t.Errorf("annotation leaked as call: %+v", c)
		}
	}
}

// TestMultipleTopLevelClasses — a .java file can legally contain one public
// class plus any number of package-private classes. Parser must emit all of
// them.
func TestMultipleTopLevelClasses(t *testing.T) {
	src := []byte(`package com.example;
public class First {
    void a() { System.out.println("1"); }
}
class Second {
    void b() { System.out.println("2"); }
}`)
	mod := Parse("First.java", src)
	if len(mod.Classes) != 2 {
		t.Fatalf("classes: got %d, want 2", len(mod.Classes))
	}
	if mod.Classes[0].Name != "First" || mod.Classes[1].Name != "Second" {
		t.Errorf("class order: %+v", mod.Classes)
	}
}

// TestFieldsAreNotMistakenForMethods — fields with method-call initializers
// must not be parsed as method declarations.
func TestFieldsAreNotMistakenForMethods(t *testing.T) {
	src := []byte(`package com.example;
import java.util.logging.Logger;
public class Foo {
    private static final Logger log = Logger.getLogger("Foo");
    void m() { log.info("x"); }
}`)
	mod := Parse("Foo.java", src)
	if len(mod.Classes) != 1 {
		t.Fatalf("classes: got %d", len(mod.Classes))
	}
	cls := mod.Classes[0]
	if len(cls.Methods) != 1 || cls.Methods[0].Name != "m" {
		t.Errorf("expected exactly one method 'm', got %+v", cls.Methods)
	}
}

// TestArgSourceTextCookieSetSecure verifies that Call instructions produced
// by the Java parser carry ArgSourceText[0] set to the verbatim source text
// of the call expression. This is required by the auth-rules engine (Task A.9).
func TestArgSourceTextCookieSetSecure(t *testing.T) {
	src := []byte(`import javax.servlet.http.*;

public class CookiePos extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) {
        Cookie c = new Cookie("session", "abc");
        c.setSecure(true);
        c.setHttpOnly(true);
        resp.addCookie(c);
    }
}`)
	mod := Parse("CookiePos.java", src)
	calls := collectCalls(mod)
	if len(calls) == 0 {
		t.Fatal("no Call instructions emitted")
	}

	// Every call must have a non-empty ArgSourceText[0].
	for _, inst := range calls {
		if len(inst.ArgSourceText) == 0 || inst.ArgSourceText[0] == "" {
			t.Errorf("Call %q (FQN=%q) has empty ArgSourceText", inst.Callee, inst.CalleeFQN)
		}
	}

	// Verify specific calls have expected source text.
	found := map[string]string{} // callee → ArgSourceText[0]
	for _, inst := range calls {
		found[inst.Callee] = inst.ArgSourceText[0]
	}

	if text, ok := found["setSecure"]; !ok {
		t.Error("setSecure call not found")
	} else if !containsSubstr(text, "setSecure") {
		t.Errorf("setSecure ArgSourceText[0] = %q; want it to contain \"setSecure\"", text)
	}

	if text, ok := found["addCookie"]; !ok {
		t.Error("addCookie call not found")
	} else if !containsSubstr(text, "addCookie") {
		t.Errorf("addCookie ArgSourceText[0] = %q; want it to contain \"addCookie\"", text)
	}

	// The constructor "new Cookie(...)" should also have ArgSourceText.
	if text, ok := found["<init>"]; !ok {
		t.Error("<init> (constructor) call not found")
	} else if !containsSubstr(text, "Cookie") {
		t.Errorf("<init> ArgSourceText[0] = %q; want it to contain \"Cookie\"", text)
	}
}

// TestJavaEnclosingFunctionTextPopulated verifies that every Call instruction
// emitted inside a method body has EnclosingFunctionText set to the verbatim
// source text of that method body, and that the text contains sibling calls
// visible in the same scope. This is required by cookie security rules that
// need to detect addCookie calls where setSecure was NOT called in the same
// method.
func TestJavaEnclosingFunctionTextPopulated(t *testing.T) {
	src := []byte(`
import javax.servlet.http.*;

public class Demo extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) {
        Cookie c = new Cookie("session", "abc");
        c.setSecure(true);
        c.setHttpOnly(true);
        resp.addCookie(c);
    }
}
`)
	mod := ParseSource("test.java", src)
	var found *ir.Instruction
	for _, c := range mod.Classes {
		for _, m := range c.Methods {
			for _, b := range m.Blocks {
				for _, inst := range b.Instructions {
					if inst.Op == ir.OpCall && inst.Callee == "addCookie" {
						found = inst
					}
				}
			}
		}
	}
	if found == nil {
		t.Fatal("addCookie call not found")
	}
	if found.EnclosingFunctionText == "" {
		t.Fatal("EnclosingFunctionText not populated")
	}
	if !containsSubstr(found.EnclosingFunctionText, "setSecure(true)") {
		t.Errorf("expected EnclosingFunctionText to contain 'setSecure(true)', got: %q", found.EnclosingFunctionText)
	}
	if !containsSubstr(found.EnclosingFunctionText, "addCookie(c)") {
		t.Errorf("expected EnclosingFunctionText to contain 'addCookie(c)', got: %q", found.EnclosingFunctionText)
	}
}

func containsSubstr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}

func collectCalls(mod *ir.Module) []*ir.Instruction {
	var out []*ir.Instruction
	for _, c := range mod.Classes {
		for _, m := range c.Methods {
			for _, b := range m.Blocks {
				for _, inst := range b.Instructions {
					if inst.Op == ir.OpCall {
						out = append(out, inst)
					}
				}
			}
		}
	}
	return out
}
