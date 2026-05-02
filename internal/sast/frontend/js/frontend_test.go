package js

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/sast/engine"
	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
)

func mustEngine(t *testing.T) *engine.Engine {
	t.Helper()
	eng, err := engine.NewFromBuiltins()
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func mustParseJS(t *testing.T, filename string) *ir.Module {
	t.Helper()
	mod, err := ParseFile(filepath.Join("testdata", filename), "testdata/"+filename)
	if err != nil {
		t.Fatal(err)
	}
	return mod
}

func filterByRule(findings []engine.Finding, ruleID string) []engine.Finding {
	var out []engine.Finding
	for _, f := range findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

// --- Parser tests ---

func TestJSParserFunctionDetection(t *testing.T) {
	src := []byte(`
const express = require("express");
function handleRequest(req, res) {
  const name = req.query.name;
  res.send("Hello " + name);
}
module.exports = { handleRequest };
`)
	mod := ParseSource("test.js", src)
	if mod.Language != "javascript" {
		t.Errorf("language: %q", mod.Language)
	}
	var foundFunc bool
	for _, c := range mod.Classes {
		for _, m := range c.Methods {
			if m.Name == "handleRequest" {
				foundFunc = true
				if len(m.Parameters) < 2 {
					t.Errorf("expected 2 params, got %d", len(m.Parameters))
				}
			}
		}
	}
	if !foundFunc {
		t.Error("handleRequest function not found")
	}
}

func TestJSParserImportDetection(t *testing.T) {
	src := []byte(`
import express from "express";
import { readFile } from "fs";
const path = require("path");
`)
	mod := ParseSource("test.js", src)
	if len(mod.Imports) < 2 {
		t.Errorf("expected at least 2 imports, got %d", len(mod.Imports))
	}
}

// --- E2E detection tests ---

func TestJSCommandInjection(t *testing.T) {
	eng := mustEngine(t)
	mod := mustParseJS(t, "cmd-injection-vuln.js")
	findings := eng.AnalyzeAll([]*ir.Module{mod})
	cmd := filterByRule(findings, "SC-JS-CMD-001")
	if len(cmd) < 1 {
		t.Fatalf("expected command injection finding, got %d. All: %+v", len(cmd), ruleIDs(findings))
	}
	t.Logf("SUCCESS: JS command injection detected (%d findings)", len(cmd))
}

func TestJSPathTraversal(t *testing.T) {
	eng := mustEngine(t)
	mod := mustParseJS(t, "path-traversal-vuln.js")
	findings := eng.AnalyzeAll([]*ir.Module{mod})
	path := filterByRule(findings, "SC-JS-PATH-001")
	if len(path) < 1 {
		t.Fatalf("expected path traversal finding, got %d. All: %+v", len(path), ruleIDs(findings))
	}
	t.Logf("SUCCESS: JS path traversal detected (%d findings)", len(path))
}

func TestJSEvalInjection(t *testing.T) {
	eng := mustEngine(t)
	mod := mustParseJS(t, "eval-vuln.js")
	findings := eng.AnalyzeAll([]*ir.Module{mod})
	ev := filterByRule(findings, "SC-JS-EVAL-001")
	if len(ev) < 1 {
		t.Fatalf("expected eval finding, got %d. All: %+v", len(ev), ruleIDs(findings))
	}
	t.Logf("SUCCESS: JS eval injection detected (%d findings)", len(ev))
}

func TestJSHardcodedSecret(t *testing.T) {
	eng := mustEngine(t)
	mod := mustParseJS(t, "hardcoded-secret.js")
	findings := eng.AnalyzeAll([]*ir.Module{mod})
	sec := filterByRule(findings, "SC-JS-SECRET-001")
	if len(sec) < 1 {
		t.Fatalf("expected hardcoded secret finding, got %d. All: %+v", len(sec), ruleIDs(findings))
	}
	t.Logf("SUCCESS: JS hardcoded secret detected (%d findings)", len(sec))
}

func TestJSSafeAppNoFindings(t *testing.T) {
	eng := mustEngine(t)
	mod := mustParseJS(t, "safe-app.js")
	findings := eng.AnalyzeAll([]*ir.Module{mod})
	// Filter to JS rules only.
	var jsFindings []engine.Finding
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "SC-JS-") {
			jsFindings = append(jsFindings, f)
		}
	}
	if len(jsFindings) != 0 {
		t.Errorf("expected 0 JS findings for safe app, got %d: %+v", len(jsFindings), ruleIDs(jsFindings))
	}
}

func TestJSWalkFiles(t *testing.T) {
	files, err := WalkJSFiles("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 6 {
		t.Errorf("expected at least 6 JS files, got %d", len(files))
	}
}

func ruleIDs(findings []engine.Finding) []string {
	var ids []string
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	return ids
}
