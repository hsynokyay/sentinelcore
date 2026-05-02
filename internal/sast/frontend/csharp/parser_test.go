package csharp

import (
	"strings"
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
)

// helper: find first call with the given callee anywhere in the module.
func findCall(mod *ir.Module, callee string) *ir.Instruction {
	for _, cls := range mod.Classes {
		for _, fn := range cls.Methods {
			for _, bb := range fn.Blocks {
				for _, inst := range bb.Instructions {
					if inst.Op == ir.OpCall && inst.Callee == callee {
						return inst
					}
				}
			}
		}
	}
	return nil
}

// helper: count store instructions across the module.
func countStores(mod *ir.Module) int {
	n := 0
	for _, cls := range mod.Classes {
		for _, fn := range cls.Methods {
			for _, bb := range fn.Blocks {
				for _, inst := range bb.Instructions {
					if inst.Op == ir.OpStore {
						n++
					}
				}
			}
		}
	}
	return n
}

func TestParseEmptyClass(t *testing.T) {
	src := []byte(`
namespace Foo.Bar {
    public class Baz {
    }
}
`)
	mod := Parse("test.cs", src)
	if mod.Language != "csharp" {
		t.Errorf("language: got %q, want csharp", mod.Language)
	}
	if mod.Package != "Foo.Bar" {
		t.Errorf("package: got %q, want Foo.Bar", mod.Package)
	}
	if len(mod.Classes) != 1 {
		t.Fatalf("got %d classes, want 1", len(mod.Classes))
	}
	if mod.Classes[0].Name != "Baz" || mod.Classes[0].FQN != "Foo.Bar.Baz" {
		t.Errorf("class: got %+v", mod.Classes[0])
	}
}

func TestParseFileScopedNamespace(t *testing.T) {
	src := []byte(`
namespace Foo.Bar;

public class Baz {
    public void M() { }
}
`)
	mod := Parse("test.cs", src)
	if mod.Package != "Foo.Bar" {
		t.Errorf("file-scoped namespace: got %q, want Foo.Bar", mod.Package)
	}
	if len(mod.Classes) != 1 || mod.Classes[0].FQN != "Foo.Bar.Baz" {
		t.Errorf("class FQN: got %+v", mod.Classes[0])
	}
}

func TestParseMethodCall(t *testing.T) {
	src := []byte(`
using System.Diagnostics;

namespace App {
    public class Launcher {
        public void Run() {
            Process.Start("notepad.exe");
        }
    }
}
`)
	mod := Parse("test.cs", src)
	call := findCall(mod, "Start")
	if call == nil {
		t.Fatal("did not find Start() call")
	}
	if call.ReceiverType != "System.Diagnostics.Process" {
		t.Errorf("receiver: got %q, want System.Diagnostics.Process", call.ReceiverType)
	}
	if len(call.Operands) != 1 || call.Operands[0].Kind != ir.OperandConstString || call.Operands[0].StrVal != "notepad.exe" {
		t.Errorf("operand: %+v", call.Operands)
	}
}

func TestParseConstructorCall(t *testing.T) {
	src := []byte(`
using System.Data.SqlClient;

namespace App {
    public class Repo {
        public void Exec(string sql) {
            var cmd = new SqlCommand(sql);
        }
    }
}
`)
	mod := Parse("test.cs", src)
	call := findCall(mod, "<init>")
	if call == nil {
		t.Fatal("did not find constructor <init> call")
	}
	if call.ReceiverType != "System.Data.SqlClient.SqlCommand" {
		t.Errorf("constructor receiver: got %q", call.ReceiverType)
	}
	if len(call.Operands) != 1 || call.Operands[0].Kind != ir.OperandValue {
		t.Errorf("constructor operand: %+v", call.Operands)
	}
}

func TestParseStringConcatTaint(t *testing.T) {
	src := []byte(`
namespace App {
    public class Repo {
        public void Exec(string userId) {
            string sql = "SELECT * FROM users WHERE id = " + userId;
        }
    }
}
`)
	mod := Parse("test.cs", src)
	// Expect at least one BinOp instruction for the concat.
	foundBinOp := false
	for _, cls := range mod.Classes {
		for _, fn := range cls.Methods {
			for _, bb := range fn.Blocks {
				for _, inst := range bb.Instructions {
					if inst.Op == ir.OpBinOp && inst.Callee == "+" {
						foundBinOp = true
					}
				}
			}
		}
	}
	if !foundBinOp {
		t.Error("expected BinOp for string concatenation")
	}
}

func TestParseInterpolatedStringTaint(t *testing.T) {
	src := []byte(`
namespace App {
    public class Repo {
        public void Exec(string userId) {
            string sql = $"SELECT * FROM users WHERE id = {userId}";
        }
    }
}
`)
	mod := Parse("test.cs", src)
	// The interpolated string should emit a BinOp joining the string const
	// with the userId parameter value.
	foundBinOp := false
	for _, cls := range mod.Classes {
		for _, fn := range cls.Methods {
			for _, bb := range fn.Blocks {
				for _, inst := range bb.Instructions {
					if inst.Op == ir.OpBinOp {
						foundBinOp = true
					}
				}
			}
		}
	}
	if !foundBinOp {
		t.Error("expected BinOp from interpolated string propagating taint")
	}
}

func TestParseFieldInitEmitsStore(t *testing.T) {
	src := []byte(`
namespace App {
    public class Config {
        private static readonly string ApiKey = "sk_live_abcdef1234567890";
    }
}
`)
	mod := Parse("test.cs", src)
	n := countStores(mod)
	if n == 0 {
		t.Error("expected at least one Store instruction for field initializer")
	}
	// Also check that the <clinit> synthetic method exists.
	found := false
	for _, cls := range mod.Classes {
		for _, fn := range cls.Methods {
			if fn.Name == "<clinit>" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected synthetic <clinit> method on class")
	}
}

func TestParseParameterTypeResolution(t *testing.T) {
	src := []byte(`
using Microsoft.AspNetCore.Http;

namespace App {
    public class Handler {
        public void Handle(HttpRequest request) {
            var id = request.Query["id"];
        }
    }
}
`)
	mod := Parse("test.cs", src)
	// The indexer access `request.Query["id"]` should be emitted as a call
	// to Query with ReceiverType resolved to HttpRequest via the parameter
	// declared type.
	call := findCall(mod, "Query")
	if call == nil {
		t.Fatal("did not find .Query indexer call")
	}
	if !strings.Contains(call.ReceiverType, "HttpRequest") {
		t.Errorf("receiver should resolve to HttpRequest, got %q", call.ReceiverType)
	}
	if len(call.Operands) != 1 || call.Operands[0].Kind != ir.OperandConstString || call.Operands[0].StrVal != "id" {
		t.Errorf("indexer key: got %+v, want const_string 'id'", call.Operands)
	}
}

func TestParseIgnoresAttributes(t *testing.T) {
	src := []byte(`
namespace App {
    [ApiController]
    [Route("api/v1")]
    public class UserController {
        [HttpGet]
        public void List() {
            Console.WriteLine("ok");
        }
    }
}
`)
	mod := Parse("test.cs", src)
	if len(mod.Classes) == 0 || mod.Classes[0].Name != "UserController" {
		t.Fatal("attributes should be skipped, class should still parse")
	}
	if len(mod.Classes[0].Methods) == 0 {
		t.Error("method should parse despite attribute")
	}
}

func TestParseUsingAlias(t *testing.T) {
	src := []byte(`
using Proc = System.Diagnostics.Process;
namespace App {
    public class L {
        public void Run() {
            Proc.Start("x");
        }
    }
}
`)
	mod := Parse("test.cs", src)
	call := findCall(mod, "Start")
	if call == nil {
		t.Fatal("no Start call")
	}
	if call.ReceiverType != "System.Diagnostics.Process" {
		t.Errorf("alias resolution: got %q", call.ReceiverType)
	}
}

func TestParseResilientToUnterminatedString(t *testing.T) {
	src := []byte(`public class Foo { string x = "unterminated`)
	_ = Parse("test.cs", src)
	// Should not crash; no assertions on content.
}

func TestParseNestedCalls(t *testing.T) {
	src := []byte(`
namespace App {
    public class Foo {
        public void Bar(string a) {
            Process.Start(Path.Combine("/tmp", a));
        }
    }
}
`)
	mod := Parse("test.cs", src)
	// Both Start and Combine calls should be emitted.
	if findCall(mod, "Start") == nil {
		t.Error("missing Start call")
	}
	if findCall(mod, "Combine") == nil {
		t.Error("missing nested Combine call")
	}
}

func TestParseUsingWildcard(t *testing.T) {
	src := []byte(`
using System.IO;

namespace App {
    public class Reader {
        public void R() {
            File.ReadAllText("x.txt");
        }
    }
}
`)
	mod := Parse("test.cs", src)
	call := findCall(mod, "ReadAllText")
	if call == nil {
		t.Fatal("no ReadAllText call")
	}
	if call.ReceiverType != "System.IO.File" {
		t.Errorf("File receiver: got %q", call.ReceiverType)
	}
}

func TestArgSourceTextCookieAppend(t *testing.T) {
	src := []byte(`
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;

public class CookieController : Controller
{
    public IActionResult Login()
    {
        Response.Cookies.Append("session", "abc", new CookieOptions { Secure = true, HttpOnly = true });
        return Ok();
    }
}
`)
	mod := Parse("test.cs", src)
	call := findCall(mod, "Append")
	if call == nil {
		t.Fatal("did not find Cookies.Append() call")
	}
	if len(call.ArgSourceText) == 0 {
		t.Fatal("ArgSourceText is empty for Cookies.Append call")
	}
	text := call.ArgSourceText[0]
	if !strings.Contains(text, "Secure") {
		t.Errorf("ArgSourceText[0] should contain 'Secure', got: %q", text)
	}
	if !strings.Contains(text, "HttpOnly") {
		t.Errorf("ArgSourceText[0] should contain 'HttpOnly', got: %q", text)
	}
}

func TestArgSourceTextMethodCall(t *testing.T) {
	src := []byte(`
using System.Diagnostics;

namespace App {
    public class Launcher {
        public void Run() {
            Process.Start("notepad.exe");
        }
    }
}
`)
	mod := Parse("test.cs", src)
	call := findCall(mod, "Start")
	if call == nil {
		t.Fatal("did not find Start() call")
	}
	if len(call.ArgSourceText) == 0 {
		t.Fatal("ArgSourceText is empty for Start call")
	}
	if !strings.Contains(call.ArgSourceText[0], "Start") {
		t.Errorf("ArgSourceText[0] should contain 'Start', got: %q", call.ArgSourceText[0])
	}
}

func TestArgSourceTextConstructor(t *testing.T) {
	src := []byte(`
using System.Data.SqlClient;

namespace App {
    public class Repo {
        public void Exec(string sql) {
            var cmd = new SqlCommand(sql);
        }
    }
}
`)
	mod := Parse("test.cs", src)
	call := findCall(mod, "<init>")
	if call == nil {
		t.Fatal("did not find constructor <init> call")
	}
	if len(call.ArgSourceText) == 0 {
		t.Fatal("ArgSourceText is empty for constructor call")
	}
	if !strings.Contains(call.ArgSourceText[0], "SqlCommand") {
		t.Errorf("ArgSourceText[0] should contain 'SqlCommand', got: %q", call.ArgSourceText[0])
	}
}
