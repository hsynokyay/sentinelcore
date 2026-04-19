package csharp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/sast/engine"
	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
)

// runEngine is the end-to-end helper: parse the source, run the full SAST
// engine (builtins + taint + rules), return findings.
func runEngine(t *testing.T, src string) []engine.Finding {
	t.Helper()
	eng, err := engine.NewFromBuiltins()
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}
	mod := Parse("test.cs", []byte(src))
	return eng.AnalyzeAll([]*ir.Module{mod})
}

func findRule(findings []engine.Finding, ruleID string) *engine.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

// --- Command Injection ---

func TestCSharpCommandInjectionVulnerable(t *testing.T) {
	src := `
using System.Diagnostics;
using Microsoft.AspNetCore.Http;

namespace App {
    public class Handler {
        public void Run(HttpRequest request) {
            string cmd = request.Query["cmd"];
            Process.Start(cmd);
        }
    }
}
`
	findings := runEngine(t, src)
	if findRule(findings, "SC-CSHARP-CMD-001") == nil {
		t.Errorf("expected SC-CSHARP-CMD-001, got findings: %+v", findings)
	}
}

func TestCSharpCommandInjectionSafe(t *testing.T) {
	src := `
using System.Diagnostics;

namespace App {
    public class Handler {
        public void Run() {
            Process.Start("notepad.exe");
        }
    }
}
`
	findings := runEngine(t, src)
	if f := findRule(findings, "SC-CSHARP-CMD-001"); f != nil {
		t.Errorf("expected NO finding on hardcoded command, got %+v", f)
	}
}

// --- Path Traversal ---

func TestCSharpPathTraversalVulnerable(t *testing.T) {
	src := `
using System.IO;
using Microsoft.AspNetCore.Http;

namespace App {
    public class Handler {
        public void Read(HttpRequest request) {
            string filename = request.Query["file"];
            string content = File.ReadAllText(filename);
        }
    }
}
`
	findings := runEngine(t, src)
	if findRule(findings, "SC-CSHARP-PATH-001") == nil {
		t.Errorf("expected SC-CSHARP-PATH-001, got: %+v", findings)
	}
}

func TestCSharpPathTraversalSafe(t *testing.T) {
	src := `
using System.IO;

namespace App {
    public class Handler {
        public void Read() {
            string content = File.ReadAllText("/var/data/config.json");
        }
    }
}
`
	findings := runEngine(t, src)
	if f := findRule(findings, "SC-CSHARP-PATH-001"); f != nil {
		t.Errorf("expected NO finding on hardcoded path, got %+v", f)
	}
}

// --- SQL Injection ---

func TestCSharpSqlInjectionConcat(t *testing.T) {
	src := `
using System.Data.SqlClient;
using Microsoft.AspNetCore.Http;

namespace App {
    public class Repo {
        public void Get(HttpRequest request, SqlConnection conn) {
            string id = request.Query["id"];
            var cmd = new SqlCommand("SELECT * FROM users WHERE id = " + id, conn);
            cmd.ExecuteReader();
        }
    }
}
`
	findings := runEngine(t, src)
	if findRule(findings, "SC-CSHARP-SQL-001") == nil {
		t.Errorf("expected SC-CSHARP-SQL-001 on string concat, got: %+v", findings)
	}
}

func TestCSharpSqlInjectionInterpolated(t *testing.T) {
	src := `
using System.Data.SqlClient;
using Microsoft.AspNetCore.Http;

namespace App {
    public class Repo {
        public void Get(HttpRequest request, SqlConnection conn) {
            string id = request.Query["id"];
            var cmd = new SqlCommand($"SELECT * FROM users WHERE id = {id}", conn);
            cmd.ExecuteReader();
        }
    }
}
`
	findings := runEngine(t, src)
	if findRule(findings, "SC-CSHARP-SQL-001") == nil {
		t.Errorf("expected SC-CSHARP-SQL-001 on interpolated string, got: %+v", findings)
	}
}

func TestCSharpSqlInjectionSafeParameterized(t *testing.T) {
	src := `
using System.Data.SqlClient;
using Microsoft.AspNetCore.Http;

namespace App {
    public class Repo {
        public void Get(HttpRequest request, SqlConnection conn) {
            string id = request.Query["id"];
            var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn);
            cmd.Parameters.AddWithValue("@id", id);
            cmd.ExecuteReader();
        }
    }
}
`
	findings := runEngine(t, src)
	if f := findRule(findings, "SC-CSHARP-SQL-001"); f != nil {
		t.Errorf("expected NO finding on parameterized query, got %+v", f)
	}
}

// --- Unsafe Deserialization ---

func TestCSharpDeserVulnerable(t *testing.T) {
	src := `
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.AspNetCore.Http;

namespace App {
    public class Handler {
        public void Load(HttpRequest request) {
            var fmt = new BinaryFormatter();
            var stream = request.Body;
            var obj = fmt.Deserialize(stream);
        }
    }
}
`
	findings := runEngine(t, src)
	if findRule(findings, "SC-CSHARP-DESER-001") == nil {
		t.Errorf("expected SC-CSHARP-DESER-001, got: %+v", findings)
	}
}

// --- SSRF ---

func TestCSharpSsrfVulnerable(t *testing.T) {
	src := `
using System.Net.Http;
using Microsoft.AspNetCore.Http;

namespace App {
    public class Fetcher {
        public void Get(HttpRequest request, HttpClient client) {
            string url = request.Query["url"];
            var res = client.GetAsync(url);
        }
    }
}
`
	findings := runEngine(t, src)
	if findRule(findings, "SC-CSHARP-SSRF-001") == nil {
		t.Errorf("expected SC-CSHARP-SSRF-001, got: %+v", findings)
	}
}

func TestCSharpSsrfSafe(t *testing.T) {
	src := `
using System.Net.Http;

namespace App {
    public class Fetcher {
        public void Get(HttpClient client) {
            var res = client.GetAsync("https://api.example.com/data");
        }
    }
}
`
	findings := runEngine(t, src)
	if f := findRule(findings, "SC-CSHARP-SSRF-001"); f != nil {
		t.Errorf("expected NO finding on hardcoded URL, got %+v", f)
	}
}

// --- Hardcoded Secret ---

func TestCSharpHardcodedSecretVulnerable(t *testing.T) {
	src := `
namespace App {
    public class Config {
        private static readonly string ApiKey = "sk_live_abcdef1234567890abcdef";
    }
}
`
	findings := runEngine(t, src)
	if findRule(findings, "SC-CSHARP-SECRET-001") == nil {
		t.Errorf("expected SC-CSHARP-SECRET-001, got: %+v", findings)
	}
}

func TestCSharpHardcodedSecretSafe(t *testing.T) {
	src := `
using System;

namespace App {
    public class Config {
        private static readonly string ApiKey = "changeme";
    }
}
`
	findings := runEngine(t, src)
	if f := findRule(findings, "SC-CSHARP-SECRET-001"); f != nil {
		t.Errorf("expected NO finding on placeholder, got %+v", f)
	}
}

// --- WalkCSharpFiles ---

func TestWalkCSharpFiles(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"Program.cs":               "namespace X { class P {} }",
		"nested/Foo.cs":            "namespace X { class F {} }",
		"bin/Release/Built.cs":     "namespace X { class B {} }", // should be skipped
		"obj/Temp.cs":              "namespace X { class T {} }", // should be skipped
		"Generated.g.cs":           "namespace X { class G {} }", // should be skipped
		"Form1.Designer.cs":        "namespace X { class D {} }", // should be skipped
		"README.md":                "not C#",
	}
	for rel, content := range files {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := WalkCSharpFiles(dir)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(paths) != 2 {
		t.Errorf("expected 2 .cs files (Program.cs, nested/Foo.cs), got %d: %v", len(paths), paths)
	}
}
