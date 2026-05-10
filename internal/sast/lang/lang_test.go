package lang

import "testing"

func TestForExtension(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		// Java
		{"Foo.java", "java"},
		{"src/main/java/com/example/Foo.java", "java"},
		{"/abs/path/A.JAVA", "java"}, // case-insensitive

		// Python
		{"foo.py", "python"},
		{"pkg/module.py", "python"},

		// JavaScript family — every dialect collapses to "javascript"
		{"app.js", "javascript"},
		{"app.mjs", "javascript"},
		{"app.cjs", "javascript"},
		{"App.jsx", "javascript"},
		{"App.tsx", "javascript"},
		{"app.ts", "javascript"},

		// C#
		{"Foo.cs", "csharp"},
		{"Areas/Admin/Bar.cs", "csharp"},

		// Unknown / no extension
		{"README.md", ""},
		{"Makefile", ""},
		{"pom.xml", ""},
		{"", ""},
		{"justaname", ""},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := ForExtension(tc.path); got != tc.want {
				t.Fatalf("ForExtension(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}
