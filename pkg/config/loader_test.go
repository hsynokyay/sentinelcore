package config

import (
	"os"
	"testing"
)

type testConfig struct {
	DBHost   string   `required:"true"`
	DBPort   int      `default:"5432"`
	Debug    bool     `default:"false"`
	Tags     []string `default:"a,b,c"`
	Optional string
}

func TestLoad_Basic(t *testing.T) {
	os.Setenv("SENTINELCORE_DB_HOST", "myhost")
	os.Setenv("SENTINELCORE_DB_PORT", "3306")
	os.Setenv("SENTINELCORE_DEBUG", "true")
	os.Setenv("SENTINELCORE_TAGS", "x,y,z")
	defer func() {
		os.Unsetenv("SENTINELCORE_DB_HOST")
		os.Unsetenv("SENTINELCORE_DB_PORT")
		os.Unsetenv("SENTINELCORE_DEBUG")
		os.Unsetenv("SENTINELCORE_TAGS")
	}()

	var cfg testConfig
	if err := Load(&cfg); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.DBHost != "myhost" {
		t.Errorf("DBHost = %q, want %q", cfg.DBHost, "myhost")
	}
	if cfg.DBPort != 3306 {
		t.Errorf("DBPort = %d, want %d", cfg.DBPort, 3306)
	}
	if !cfg.Debug {
		t.Error("Debug should be true")
	}
	if len(cfg.Tags) != 3 || cfg.Tags[0] != "x" {
		t.Errorf("Tags = %v, want [x y z]", cfg.Tags)
	}
}

func TestLoad_Defaults(t *testing.T) {
	os.Setenv("SENTINELCORE_DB_HOST", "localhost")
	defer os.Unsetenv("SENTINELCORE_DB_HOST")

	var cfg testConfig
	if err := Load(&cfg); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.DBPort != 5432 {
		t.Errorf("DBPort = %d, want default 5432", cfg.DBPort)
	}
	if cfg.Debug {
		t.Error("Debug should default to false")
	}
}

func TestLoad_RequiredMissing(t *testing.T) {
	os.Unsetenv("SENTINELCORE_DB_HOST")
	var cfg testConfig
	err := Load(&cfg)
	if err == nil {
		t.Fatal("expected error for missing required field")
	}
}

func TestLoad_NonPointer(t *testing.T) {
	var cfg testConfig
	err := Load(cfg)
	if err == nil {
		t.Fatal("expected error for non-pointer")
	}
}

func TestCamelToUpperSnake(t *testing.T) {
	tests := []struct{ in, want string }{
		{"DBHost", "DB_HOST"},
		{"DBPort", "DB_PORT"},
		{"MaxConns", "MAX_CONNS"},
		{"URL", "URL"},
		{"Debug", "DEBUG"},
		{"MyHTTPServer", "MY_HTTP_SERVER"},
	}
	for _, tt := range tests {
		got := camelToUpperSnake(tt.in)
		if got != tt.want {
			t.Errorf("camelToUpperSnake(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
