# Auth / Authz / Session SAST Rules — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 36 new SAST rules covering cookie attributes, JWT validation, session management, authorization-header injection, and CSRF unsafe comparisons across Python/JavaScript/Java/C#. One small engine extension (`arg_text_contains_any` / `arg_text_missing_any`) supports object-key-presence matching for cookie-attribute rules.

**Architecture:** Four independently-deployable PRs. PR A extends the IR Call instruction with `ArgSourceText` (one source-text span per operand) and adds two new pattern matchers. PR B ships 12 cookie rules + 4 framework models. PR C ships 12 JWT + 5 session + 4 auth-header rules + 4 framework models (largest PR). PR D ships 3 CSRF rules. Each PR builds the controlplane image and deploys via the production compose stack.

**Tech Stack:** Go 1.23 (controlplane + sast worker), structured rule JSONs in `internal/sast/rules/builtins/`, framework-model JSONs in `internal/sast/engine/models/`, AST frontends in `internal/sast/frontend/{python,js,java,csharp}/parser.go`, fixture-driven detection tests in `internal/sast/worker_test.go`.

**Spec reference:** `docs/superpowers/specs/2026-05-02-auth-authz-session-design.md`

---

## Working environment

- **Branch:** `feat/auth-rules-2026-05` cut from `phase2/api-dast` HEAD (commit `911f883f` — the spec commit).
- **Worktree:** `/Users/okyay/Documents/SentinelCore/.worktrees/auth-rules` (created in PR pre-flight).
- **Build target:** `sentinelcore/controlplane:pilot` is shared by the API and the SAST worker; rebuild it for each PR.
- **SAST worker target:** `sentinelcore/sast-worker:pilot` — note that the SAST rules are embedded into the worker binary, so the worker image is the one that needs rebuilding for rules to take effect at scan time. The controlplane image is rebuilt for parity.
- **Server build:**
  ```
  rsync -az --delete --exclude .git --exclude '*.test' \
    internal/ migrations/ pkg/ rules/ scripts/ Dockerfile go.mod go.sum cmd/ \
    okyay@77.42.34.174:/tmp/sentinelcore-src/
  ssh okyay@77.42.34.174 "cd /tmp/sentinelcore-src && \
    docker build -t sentinelcore/controlplane:auth-prN . && \
    docker build -f cmd/sast-worker/Dockerfile -t sentinelcore/sast-worker:auth-prN ."
  ```
- **Deploy:**
  ```
  ssh okyay@77.42.34.174 "docker tag sentinelcore/controlplane:auth-prN sentinelcore/controlplane:pilot && \
    docker tag sentinelcore/sast-worker:auth-prN sentinelcore/sast-worker:pilot && \
    cd /opt/sentinelcore/compose && docker compose up -d controlplane sast_worker"
  ```
- **Rollback tags** (taken once before PR A):
  ```
  ssh okyay@77.42.34.174 "docker tag sentinelcore/controlplane:pilot sentinelcore/controlplane:pilot-pre-auth && \
    docker tag sentinelcore/sast-worker:pilot sentinelcore/sast-worker:pilot-pre-auth"
  ```
- **GitHub push:** after each PR's commits land in the worktree, `git push -u origin feat/auth-rules-2026-05` (first push) or `git push` (subsequent).

---

## Existing rule inventory (verified post-PR #7 merge)

64 structured rules across 4 languages covering 17 vuln classes (cmd, crypto, deser, eval, log, path, redirect, secret, sql, ssrf, xss, xxe, ssti, nosql_injection, prototype_pollution, mass_assignment, http_header_injection). Detection-kind distribution: ~50 taint, ~12 ast_call, ~2 ast_assign.

Auth-related rules in current set: **none.** Faz 8 fills this entire vuln class.

---

## File structure

### New files

| Path | Responsibility |
|------|----------------|
| `internal/sast/engine/models/python-cookie.json` | Flask `Response.set_cookie`, Django `HttpResponse.set_cookie` sinks |
| `internal/sast/engine/models/js-cookie.json` | Express `res.cookie`, `cookie-session`, `express-session` sinks |
| `internal/sast/engine/models/java-cookie.json` | Servlet `Cookie` setters, Spring `ResponseCookie.builder` sinks |
| `internal/sast/engine/models/csharp-cookie.json` | ASP.NET `CookieOptions` initializer sinks |
| `internal/sast/engine/models/python-jwt.json` | pyjwt `decode` sinks |
| `internal/sast/engine/models/js-jwt.json` | jsonwebtoken `verify`/`decode` sinks |
| `internal/sast/engine/models/java-jwt.json` | jjwt `Jwts.parser` sinks |
| `internal/sast/engine/models/csharp-jwt.json` | System.IdentityModel `JwtSecurityTokenHandler` sinks |
| `internal/sast/engine/models/python-session.json` | Flask `session` mutation sinks |
| `internal/sast/engine/models/java-session.json` | Servlet `HttpSession` setters |
| `internal/sast/engine/models/csharp-session.json` | ASP.NET `Session` setters |
| `internal/sast/engine/models/js-csrf.json` | csurf comparison helpers |
| `internal/sast/engine/models/python-csrf.json` | Flask-WTF token compare |
| `internal/sast/engine/models/java-csrf.json` | Spring CSRF token compare |
| `internal/sast/rules/builtins/SC-PY-COOKIE-001.json` (×3) | Python cookie attribute rules |
| `internal/sast/rules/builtins/SC-JS-COOKIE-001.json` (×3) | JS cookie attribute rules |
| `internal/sast/rules/builtins/SC-JAVA-COOKIE-001.json` (×3) | Java cookie attribute rules |
| `internal/sast/rules/builtins/SC-CSHARP-COOKIE-001.json` (×3) | C# cookie attribute rules |
| `internal/sast/rules/builtins/SC-{LANG}-JWT-{001..003}.json` (12) | JWT rules |
| `internal/sast/rules/builtins/SC-JS-SESSION-001.json` | JS predictable session ID |
| `internal/sast/rules/builtins/SC-JAVA-SESSION-001.json` | Java predictable session ID |
| `internal/sast/rules/builtins/SC-CSHARP-SESSION-001.json` | C# predictable session ID |
| `internal/sast/rules/builtins/SC-PY-SESSION-002.json` | Flask missing session.regenerate |
| `internal/sast/rules/builtins/SC-JAVA-SESSION-002.json` | Servlet missing changeSessionId |
| `internal/sast/rules/builtins/SC-{LANG}-AUTHHEADER-001.json` (4) | Auth header injection (taint) |
| `internal/sast/rules/builtins/SC-JS-CSRF-001.json` | JS CSRF unsafe compare |
| `internal/sast/rules/builtins/SC-PY-CSRF-001.json` | Python CSRF unsafe compare |
| `internal/sast/rules/builtins/SC-JAVA-CSRF-001.json` | Java CSRF unsafe compare |
| `internal/sast/fixtures/{python,javascript,java,csharp}/cookie_{positive,negative}.{ext}` | Cookie fixtures |
| `internal/sast/fixtures/{python,javascript,java,csharp}/jwt_{positive,negative}.{ext}` | JWT fixtures |
| `internal/sast/fixtures/{javascript,java,csharp}/session_{positive,negative}.{ext}` | Session ID fixtures |
| `internal/sast/fixtures/{python,java}/session_rotate_{positive,negative}.{ext}` | Session rotation fixtures |
| `internal/sast/fixtures/{python,javascript,java,csharp}/authheader_{positive,negative}.{ext}` | Auth header fixtures |
| `internal/sast/fixtures/{javascript,python,java}/csrf_{positive,negative}.{ext}` | CSRF fixtures |

### Modified files

| Path | Reason |
|------|--------|
| `internal/sast/rules/schema.go` | Add `ArgTextContainsAny`, `ArgTextMissingAny` to `CallPattern` |
| `internal/sast/ir/ir.go` | Add `ArgSourceText []string` to `Instruction` |
| `internal/sast/ir/builder.go` | Extend `Call` builder method to accept arg-text spans |
| `internal/sast/engine/rule_engine.go` | Apply `arg_text_*` matchers in `callMatchesPattern` |
| `internal/sast/engine/adapter.go` | Wire arg-text fields into Operand-pattern matching utilities (if used) |
| `internal/sast/frontend/python/parser.go` | Populate `ArgSourceText` from AST node spans |
| `internal/sast/frontend/js/parser.go` | Populate `ArgSourceText` from tree-sitter ranges |
| `internal/sast/frontend/java/parser.go` | Populate `ArgSourceText` from JavaParser node ranges |
| `internal/sast/frontend/csharp/parser.go` | Populate `ArgSourceText` from Roslyn-style span info |
| `internal/sast/engine/models/python-stdlib.json` | Add `auth_header_injection` sink (sibling of existing `http_header_injection`) |
| `internal/sast/engine/models/js-http.json` | Same |
| `internal/sast/engine/models/java-servlet.json` | Same |
| `internal/sast/engine/models/csharp-aspnet.json` | Same |
| `internal/sast/rules/loader_test.go` | Extend assertion lists for each PR |
| `scripts/acceptance-test.sh` | Adjust hardcoded finding-count threshold |

---

## PR 0 — Pre-flight: branch + worktree + rollback tags

- [ ] **Step 1: Verify clean working tree on phase2/api-dast**

```
cd /Users/okyay/Documents/SentinelCore
git status --short
git rev-parse HEAD
```

Expected: HEAD is `911f883f` (the spec commit). Only previously-known unstaged files (`.claude/scheduled_tasks.lock`, possibly `docs/ARCHITECTURE.md M`, `deploy/docker-compose/docker-compose.yml M`). STOP if untracked files exist in `internal/sast/`.

- [ ] **Step 2: Fetch and create branch + worktree**

```
git fetch origin
git worktree add /Users/okyay/Documents/SentinelCore/.worktrees/auth-rules \
  -b feat/auth-rules-2026-05 phase2/api-dast
cd /Users/okyay/Documents/SentinelCore/.worktrees/auth-rules
git branch --show-current
```

Expected: prints `feat/auth-rules-2026-05`.

- [ ] **Step 3: Tag rollback images**

```
ssh okyay@77.42.34.174 "docker tag sentinelcore/controlplane:pilot sentinelcore/controlplane:pilot-pre-auth && \
  docker tag sentinelcore/sast-worker:pilot sentinelcore/sast-worker:pilot-pre-auth && \
  docker images | grep -E 'controlplane|sast-worker' | head -10"
```

Expected: both `pilot-pre-auth` tags listed alongside `pilot`.

- [ ] **Step 4: Sanity-check existing tests pass on the new branch**

```
cd /Users/okyay/Documents/SentinelCore/.worktrees/auth-rules
go test ./internal/sast/...
```

Expected: ok / PASS for every package. STOP if anything fails — investigate before proceeding (likely environment issue, not branch issue).

---

## PR A — Engine extension (`arg_text_contains_any` / `arg_text_missing_any`)

Adds `ArgSourceText` to the IR Call instruction, propagates it from all four AST frontends, and extends `callMatchesPattern` to evaluate two new schema fields. No rules consume the new matcher in this PR.

### Task A.1: Add `ArgSourceText` field to IR Instruction

**Files:**
- Modify: `internal/sast/ir/ir.go`

- [ ] **Step 1: Read current Instruction struct**

```
sed -n '105,125p' internal/sast/ir/ir.go
```

- [ ] **Step 2: Add the field**

Insert after the `Loc Location \`json:"loc"\`` line, before the closing `}` of `Instruction`:

```go
	// ArgSourceText is the verbatim source-text representation of each
	// operand at this call site, parallel to Operands. Empty string entries
	// are allowed for operands whose source text is unavailable. Populated
	// by the AST frontend; consumed by rule_engine.go's arg_text_* matchers.
	// Optional — older modules may have empty slices.
	ArgSourceText []string `json:"arg_source_text,omitempty"`
```

- [ ] **Step 3: Build to confirm no breakage**

```
go build ./internal/sast/ir/
```

Expected: success.

- [ ] **Step 4: Commit**

```
git add internal/sast/ir/ir.go
git commit -m "feat(sast/ir): add ArgSourceText field to Call Instruction for text-based matchers"
```

### Task A.2: Extend builder.Call to accept arg-text spans

**Files:**
- Modify: `internal/sast/ir/builder.go`

- [ ] **Step 1: Read the current builder.Call**

```
grep -n "func.*Call\|func ConstString" internal/sast/ir/builder.go | head -10
sed -n '120,145p' internal/sast/ir/builder.go
```

- [ ] **Step 2: Add a sibling method `CallWithArgText`**

Append immediately after the existing `Call` method:

```go
// CallWithArgText is like Call but also records the verbatim source text
// of each operand. argText must be the same length as ops; pass empty
// strings for operands whose source span is unavailable.
//
// Frontends that have access to AST node spans should prefer this. Pure
// constant calls (no source spans) can keep using Call.
func (b *FunctionBuilder) CallWithArgText(receiverType, callee, calleeFQN string, resultType Type, loc Location, ops []Operand, argText []string) *FunctionBuilder {
	if argText != nil && len(argText) != len(ops) {
		// Tolerate length mismatches by truncating/padding so frontends
		// don't crash the build over a missing span; pad with empty strings.
		fixed := make([]string, len(ops))
		copy(fixed, argText)
		argText = fixed
	}
	b.fn.Blocks[b.cur].Instructions = append(b.fn.Blocks[b.cur].Instructions, Instruction{
		Op:            OpCall,
		Result:        b.next(),
		ResultType:    resultType,
		Operands:      ops,
		ReceiverType:  receiverType,
		Callee:        callee,
		CalleeFQN:     calleeFQN,
		Loc:           loc,
		ArgSourceText: argText,
	})
	return b
}
```

- [ ] **Step 3: Build**

```
go build ./internal/sast/ir/
```

Expected: success.

- [ ] **Step 4: Commit**

```
git add internal/sast/ir/builder.go
git commit -m "feat(sast/ir): add CallWithArgText builder helper"
```

### Task A.3: Add `ArgTextContainsAny` / `ArgTextMissingAny` to schema

**Files:**
- Modify: `internal/sast/rules/schema.go`

- [ ] **Step 1: Read current CallPattern**

```
sed -n '69,90p' internal/sast/rules/schema.go
```

- [ ] **Step 2: Extend CallPattern**

Replace the `CallPattern` struct definition (the block starting `type CallPattern struct {`) with this version:

```go
// CallPattern matches a Call instruction in the IR. All non-empty fields
// must match; empty fields are wildcards.
//
// ReceiverFQN matches the declared type of the call receiver exactly.
// Callee matches the simple method name.
// If ArgIndex is set and ArgMatchesAny is non-empty, the operand at
// ArgIndex must be a string literal matching at least one of the supplied
// regular expressions.
//
// ArgTextContainsAny / ArgTextMissingAny operate on Instruction.ArgSourceText
// — the verbatim source-text representation of each operand. Use these for
// cookie/JWT options-object patterns where a key's presence (or absence)
// inside an object literal cannot be expressed as a string-literal regex.
type CallPattern struct {
	ReceiverFQN        string   `json:"receiver_fqn,omitempty"`
	Callee             string   `json:"callee,omitempty"`
	CalleeFQN          string   `json:"callee_fqn,omitempty"`
	ArgIndex           *int     `json:"arg_index,omitempty"`
	ArgMatchesAny      []string `json:"arg_matches_any,omitempty"`
	ArgTextContainsAny []string `json:"arg_text_contains_any,omitempty"`
	ArgTextMissingAny  []string `json:"arg_text_missing_any,omitempty"`
	// MessageTemplate is a human-readable description used in the finding
	// title when this pattern fires. Supports the placeholder {{arg}} which
	// expands to the matched string literal (or, for arg_text_* matchers,
	// the operand source text).
	MessageTemplate string `json:"message_template,omitempty"`
}
```

- [ ] **Step 3: Build**

```
go build ./internal/sast/rules/
```

Expected: success.

- [ ] **Step 4: Commit**

```
git add internal/sast/rules/schema.go
git commit -m "feat(sast/rules): add ArgTextContainsAny/ArgTextMissingAny to CallPattern"
```

### Task A.4: Implement matchers in rule_engine.go

**Files:**
- Modify: `internal/sast/engine/rule_engine.go`

- [ ] **Step 1: Read current callMatchesPattern**

```
grep -n "callMatchesPattern" internal/sast/engine/rule_engine.go
sed -n '54,110p' internal/sast/engine/rule_engine.go
```

- [ ] **Step 2: Locate the end of callMatchesPattern**

The existing function returns `true` after handling `ArgIndex`/`ArgMatchesAny`. We need to add two new checks BEFORE that final `return true`. Read whatever is between the `ArgIndex/ArgMatchesAny` block and the closing brace.

```
sed -n '67,100p' internal/sast/engine/rule_engine.go
```

- [ ] **Step 3: Insert the new matchers**

Find the line `if src.ArgIndex != nil && len(p.ArgRegexes) > 0 {` and the closing `}` of that block. Immediately after that block (before `return true`), insert:

```go
	// arg_text_contains_any / arg_text_missing_any: operate on the source-text
	// representation of operands. ArgIndex is required; if absent or out of
	// range we fail closed (no match).
	if len(src.ArgTextContainsAny) > 0 || len(src.ArgTextMissingAny) > 0 {
		if src.ArgIndex == nil {
			return false
		}
		idx := *src.ArgIndex
		if idx < 0 || idx >= len(inst.ArgSourceText) {
			return false
		}
		text := inst.ArgSourceText[idx]
		if len(src.ArgTextContainsAny) > 0 {
			any := false
			for _, needle := range src.ArgTextContainsAny {
				if needle != "" && strings.Contains(text, needle) {
					any = true
					break
				}
			}
			if !any {
				return false
			}
		}
		if len(src.ArgTextMissingAny) > 0 {
			missing := false
			for _, needle := range src.ArgTextMissingAny {
				if needle != "" && !strings.Contains(text, needle) {
					missing = true
					break
				}
			}
			if !missing {
				return false
			}
		}
	}
```

- [ ] **Step 4: Build**

```
go build ./internal/sast/engine/
```

Expected: success.

- [ ] **Step 5: Commit**

```
git add internal/sast/engine/rule_engine.go
git commit -m "feat(sast/engine): implement arg_text_contains_any/missing_any matchers"
```

### Task A.5: Compile new fields in rule loader

**Files:**
- Modify: `internal/sast/rules/loader.go`

- [ ] **Step 1: Find CompiledPattern struct**

```
grep -n "CompiledPattern\|ArgRegexes" internal/sast/rules/loader.go
sed -n '1,40p' internal/sast/rules/loader.go
```

- [ ] **Step 2: Verify the loader copies CallPattern verbatim into CompiledPattern**

If `CompiledPattern.Source` already references the full `CallPattern`, no loader change is needed (the matchers in rule_engine.go read `p.Source.ArgTextContainsAny` directly). Confirm by reading where `CompiledPattern.Source` is populated:

```
grep -n "CompiledPattern{" internal/sast/rules/loader.go | head -5
```

Expected: a literal copy like `CompiledPattern{Source: pattern, ArgRegexes: ...}`. If so, **skip step 3** — schema fields flow through automatically.

- [ ] **Step 3 (only if loader doesn't carry the fields):** Add explicit copies. Skip if step 2 confirmed automatic flow.

- [ ] **Step 4: Run rule loader test**

```
go test ./internal/sast/rules/... -run TestLoadBuiltins -v 2>&1 | tail -10
```

Expected: PASS — existing rules still load.

- [ ] **Step 5: Commit (only if changes were made)**

```
git status --short internal/sast/rules/
# only commit if loader.go was modified
```

### Task A.6: Add unit test for the new matchers

**Files:**
- Create: `internal/sast/engine/arg_text_test.go`

- [ ] **Step 1: Write the test**

```go
package engine

import (
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
	"github.com/sentinelcore/sentinelcore/internal/sast/rules"
)

func TestArgTextContainsAny(t *testing.T) {
	one := 0
	pattern := rules.CompiledPattern{
		Source: rules.CallPattern{
			ReceiverFQN:        "res",
			Callee:             "cookie",
			ArgIndex:           &one,
			ArgTextContainsAny: []string{"httpOnly: false"},
		},
	}
	inst := &ir.Instruction{
		Op:           ir.OpCall,
		ReceiverType: "res",
		Callee:       "cookie",
		Operands:     []ir.Operand{{Kind: ir.OperandConstString, StrVal: "session"}, {Kind: ir.OperandValue, Value: 7}},
		ArgSourceText: []string{
			`"session"`,
			`{ httpOnly: false, secure: true }`,
		},
	}
	if !callMatchesPattern(inst, pattern) {
		t.Fatalf("expected match: text contains 'httpOnly: false'")
	}

	inst.ArgSourceText[1] = `{ httpOnly: true, secure: true }`
	if callMatchesPattern(inst, pattern) {
		t.Fatalf("expected no match when text does not contain needle")
	}
}

func TestArgTextMissingAny(t *testing.T) {
	one := 0
	pattern := rules.CompiledPattern{
		Source: rules.CallPattern{
			ReceiverFQN:       "res",
			Callee:            "cookie",
			ArgIndex:          &one,
			ArgTextMissingAny: []string{"httpOnly", "HttpOnly"},
		},
	}
	inst := &ir.Instruction{
		Op:           ir.OpCall,
		ReceiverType: "res",
		Callee:       "cookie",
		Operands:     []ir.Operand{{Kind: ir.OperandConstString, StrVal: "session"}, {Kind: ir.OperandValue, Value: 7}},
		ArgSourceText: []string{
			`"session"`,
			`{ secure: true, sameSite: "lax" }`,
		},
	}
	if !callMatchesPattern(inst, pattern) {
		t.Fatalf("expected match: 'httpOnly' missing from options text")
	}

	inst.ArgSourceText[1] = `{ httpOnly: true, secure: true }`
	if callMatchesPattern(inst, pattern) {
		t.Fatalf("expected no match when text contains needle")
	}
}

func TestArgTextMissingAny_NoArgIndex_FailsClosed(t *testing.T) {
	pattern := rules.CompiledPattern{
		Source: rules.CallPattern{
			ReceiverFQN:       "res",
			Callee:            "cookie",
			ArgTextMissingAny: []string{"httpOnly"},
		},
	}
	inst := &ir.Instruction{
		Op:           ir.OpCall,
		ReceiverType: "res",
		Callee:       "cookie",
		Operands:     []ir.Operand{{Kind: ir.OperandConstString, StrVal: "session"}},
		ArgSourceText: []string{`"session"`},
	}
	if callMatchesPattern(inst, pattern) {
		t.Fatalf("expected no match when ArgIndex is nil and arg_text_* is set")
	}
}

func TestArgTextMissingAny_OutOfRange_FailsClosed(t *testing.T) {
	five := 5
	pattern := rules.CompiledPattern{
		Source: rules.CallPattern{
			ReceiverFQN:       "res",
			Callee:            "cookie",
			ArgIndex:          &five,
			ArgTextMissingAny: []string{"httpOnly"},
		},
	}
	inst := &ir.Instruction{
		Op:           ir.OpCall,
		ReceiverType: "res",
		Callee:       "cookie",
		Operands:     []ir.Operand{{Kind: ir.OperandConstString, StrVal: "session"}},
		ArgSourceText: []string{`"session"`},
	}
	if callMatchesPattern(inst, pattern) {
		t.Fatalf("expected no match when ArgIndex is out of range")
	}
}
```

- [ ] **Step 2: Run the test**

```
go test ./internal/sast/engine/ -run "TestArgText" -v 2>&1 | tail -20
```

Expected: 4 PASS lines.

- [ ] **Step 3: Commit**

```
git add internal/sast/engine/arg_text_test.go
git commit -m "test(sast/engine): cover arg_text_contains_any/missing_any matchers"
```

### Task A.7: Wire `ArgSourceText` from Python frontend

**Files:**
- Modify: `internal/sast/frontend/python/parser.go`

- [ ] **Step 1: Locate where Call instructions are emitted**

```
grep -n "builder\.Call\|FunctionBuilder.*Call\b\|\.Call(" internal/sast/frontend/python/parser.go | head -10
```

- [ ] **Step 2: For each `builder.Call(...)` site, switch to `CallWithArgText` and pass operand source spans**

For Python AST nodes, every `ast.Call` argument has `lineno`, `col_offset`, `end_lineno`, `end_col_offset` (all 1-indexed). The parser already has access to the source bytes (look for the field `src` or `source` on the parser struct). For each call argument, slice the source between the start and end positions to get the source text.

Add a helper at the top of the file (after the existing imports):

```go
// argSpanText returns the verbatim source text for a Python AST argument
// node, or "" if span info is missing or invalid.
func (p *parser) argSpanText(line1, col1, line2, col2 int) string {
	// p.lines must be the source split by \n; if not present, see step 3.
	if line1 < 1 || line2 < 1 || line2 < line1 || line2 > len(p.lines) {
		return ""
	}
	if line1 == line2 {
		row := p.lines[line1-1]
		if col1 < 0 || col2 > len(row) || col2 < col1 {
			return ""
		}
		return row[col1:col2]
	}
	var b strings.Builder
	first := p.lines[line1-1]
	if col1 < 0 || col1 > len(first) {
		return ""
	}
	b.WriteString(first[col1:])
	for i := line1; i < line2-1; i++ {
		b.WriteString("\n")
		b.WriteString(p.lines[i])
	}
	last := p.lines[line2-1]
	if col2 < 0 || col2 > len(last) {
		return ""
	}
	b.WriteString("\n")
	b.WriteString(last[:col2])
	return b.String()
}
```

If `p.lines` does not exist, add it during parser construction (split source on `\n` once and store).

For each Call emit site, build an `argText []string` slice parallel to the operands. For each argument node, call `p.argSpanText(...)` and append. For value-only operands without span info, append `""`.

Replace `builder.Call(receiverType, callee, calleeFQN, resultType, loc, ops...)` with `builder.CallWithArgText(receiverType, callee, calleeFQN, resultType, loc, ops, argText)`.

- [ ] **Step 3: Verify the parser still compiles**

```
go build ./internal/sast/frontend/python/
```

Expected: success.

- [ ] **Step 4: Run Python frontend tests**

```
go test ./internal/sast/frontend/python/...
```

Expected: PASS (existing tests don't check ArgSourceText, so behavior is preserved). If any tests fail because of new field on Instruction, adjust the test fixture goldens.

- [ ] **Step 5: Commit**

```
git add internal/sast/frontend/python/parser.go
git commit -m "feat(sast/frontend/py): emit ArgSourceText for Call instructions"
```

### Task A.8: Wire `ArgSourceText` from JS frontend

**Files:**
- Modify: `internal/sast/frontend/js/parser.go`

- [ ] **Step 1: Locate Call emit sites**

```
grep -n "builder\.Call\|\.Call(" internal/sast/frontend/js/parser.go | head -10
```

- [ ] **Step 2: Use tree-sitter node ranges**

JS uses tree-sitter (verify with `grep -n "tree.sitter\|tree-sitter\|sitter\\.Node\|node\\.StartByte" internal/sast/frontend/js/parser.go`). For each argument node, the verbatim source text is `source[node.StartByte():node.EndByte()]`. Add a helper at the top:

```go
// nodeText returns the source text for a tree-sitter node.
func nodeText(src []byte, n *sitter.Node) string {
	if n == nil {
		return ""
	}
	start, end := n.StartByte(), n.EndByte()
	if int(start) >= len(src) || int(end) > len(src) || end < start {
		return ""
	}
	return string(src[start:end])
}
```

For each Call emit, build `argText` parallel to the operand slice and pass via `CallWithArgText`. For non-AST-derived operands, append `""`.

- [ ] **Step 3: Build + test**

```
go build ./internal/sast/frontend/js/
go test ./internal/sast/frontend/js/...
```

Expected: PASS.

- [ ] **Step 4: Commit**

```
git add internal/sast/frontend/js/parser.go
git commit -m "feat(sast/frontend/js): emit ArgSourceText for Call instructions"
```

### Task A.9: Wire `ArgSourceText` from Java frontend

**Files:**
- Modify: `internal/sast/frontend/java/parser.go`

- [ ] **Step 1: Locate Call emit sites**

```
grep -n "builder\.Call\|\.Call(" internal/sast/frontend/java/parser.go | head -10
```

- [ ] **Step 2: Use existing AST span data**

The Java frontend uses an external parser whose AST nodes carry `BeginLine`, `BeginColumn`, `EndLine`, `EndColumn` (verify with `grep -n "BeginLine\|EndLine" internal/sast/frontend/java/parser.go`). Reuse the line-slicing helper pattern from Task A.7 (Python). If `p.lines` doesn't exist, add it.

For each Call emit, build `argText` and pass via `CallWithArgText`.

- [ ] **Step 3: Build + test**

```
go build ./internal/sast/frontend/java/
go test ./internal/sast/frontend/java/...
```

- [ ] **Step 4: Commit**

```
git add internal/sast/frontend/java/parser.go
git commit -m "feat(sast/frontend/java): emit ArgSourceText for Call instructions"
```

### Task A.10: Wire `ArgSourceText` from C# frontend

**Files:**
- Modify: `internal/sast/frontend/csharp/parser.go`

- [ ] **Step 1: Locate Call emit sites**

```
grep -n "builder\.Call\|\.Call(" internal/sast/frontend/csharp/parser.go | head -10
```

- [ ] **Step 2: Use Roslyn-style span info**

The C# frontend either uses a Roslyn JSON dump or tree-sitter-c-sharp. Verify which:

```
head -40 internal/sast/frontend/csharp/parser.go
```

If JSON-based: each node JSON has `start` and `end` fields (line/col). If tree-sitter-based: same approach as Task A.8.

Add a helper, populate `argText`, pass via `CallWithArgText`.

- [ ] **Step 3: Build + test**

```
go build ./internal/sast/frontend/csharp/
go test ./internal/sast/frontend/csharp/...
```

- [ ] **Step 4: Commit**

```
git add internal/sast/frontend/csharp/parser.go
git commit -m "feat(sast/frontend/csharp): emit ArgSourceText for Call instructions"
```

### Task A.11: Run full SAST test suite + commit

- [ ] **Step 1: Run all SAST tests**

```
cd /Users/okyay/Documents/SentinelCore/.worktrees/auth-rules
go test ./internal/sast/... 2>&1 | tail -30
```

Expected: PASS for every package. Investigate any failure — most likely a frontend test that pinned a pre-ArgSourceText golden.

- [ ] **Step 2: Push branch**

```
git push -u origin feat/auth-rules-2026-05
```

### Task A.12: Build, deploy, smoke

- [ ] **Step 1: Sync source to server**

```
rsync -az --delete --exclude .git --exclude '*.test' \
  internal/ migrations/ pkg/ rules/ scripts/ Dockerfile go.mod go.sum cmd/ \
  okyay@77.42.34.174:/tmp/sentinelcore-src/
```

- [ ] **Step 2: Build images on server**

```
ssh okyay@77.42.34.174 "cd /tmp/sentinelcore-src && \
  docker build -t sentinelcore/controlplane:auth-pra . 2>&1 | tail -10 && \
  docker build -f cmd/sast-worker/Dockerfile -t sentinelcore/sast-worker:auth-pra . 2>&1 | tail -10"
```

If `cmd/sast-worker/Dockerfile` does not exist, the worker likely uses a multi-target Dockerfile or the same image — read `Dockerfile` to determine the correct target invocation. Adjust accordingly.

Expected: both builds succeed.

- [ ] **Step 3: Deploy + verify**

```
ssh okyay@77.42.34.174 "docker tag sentinelcore/controlplane:auth-pra sentinelcore/controlplane:pilot && \
  docker tag sentinelcore/sast-worker:auth-pra sentinelcore/sast-worker:pilot && \
  cd /opt/sentinelcore/compose && docker compose up -d controlplane sast_worker 2>&1 | tail -5 && \
  sleep 3 && docker ps --filter name=sentinel --format '{{.Names}}: {{.Status}}'"
curl -s -o /dev/null -w 'healthz: %{http_code}\nreadyz: %{http_code}\n' \
  https://sentinelcore.resiliencetech.com.tr/healthz
curl -s -o /dev/null -w 'readyz: %{http_code}\n' \
  https://sentinelcore.resiliencetech.com.tr/readyz
```

Expected: both endpoints 200; both containers healthy.

PR A is complete. Engine recognizes new matcher fields; no rule consumes them yet.

---

## PR B — Cookie attribute rules (12 rules)

Adds 4 framework-model JSONs (one per language) + 12 rule files (3 attributes × 4 languages) + 4 fixture pairs.

### Task B.1: Create `python-cookie.json` framework model

**Files:**
- Create: `internal/sast/engine/models/python-cookie.json`

- [ ] **Step 1: Write the file**

```json
{
  "language": "python",
  "framework": "python-cookie",
  "models": [
    {"kind": "sink", "receiver_fqn": "flask.Response", "method": "set_cookie", "vuln_class": "cookie_misconfig"},
    {"kind": "sink", "receiver_fqn": "Response", "method": "set_cookie", "vuln_class": "cookie_misconfig"},
    {"kind": "sink", "receiver_fqn": "django.http.HttpResponse", "method": "set_cookie", "vuln_class": "cookie_misconfig"},
    {"kind": "sink", "receiver_fqn": "HttpResponse", "method": "set_cookie", "vuln_class": "cookie_misconfig"},
    {"kind": "sink", "receiver_fqn": "response", "method": "set_cookie", "vuln_class": "cookie_misconfig"}
  ]
}
```

- [ ] **Step 2: Validate JSON**

```
python3 -c "import json; json.load(open('internal/sast/engine/models/python-cookie.json'))" && echo OK
```

- [ ] **Step 3: Commit + push**

```
git add internal/sast/engine/models/python-cookie.json
git commit -m "feat(sast): add python-cookie framework model"
git push
```

### Task B.2: Create `js-cookie.json` framework model

**Files:**
- Create: `internal/sast/engine/models/js-cookie.json`

- [ ] **Step 1: Write the file**

```json
{
  "language": "javascript",
  "framework": "js-cookie",
  "models": [
    {"kind": "sink", "receiver_fqn": "res", "method": "cookie", "vuln_class": "cookie_misconfig"},
    {"kind": "sink", "receiver_fqn": "response", "method": "cookie", "vuln_class": "cookie_misconfig"},
    {"kind": "sink", "receiver_fqn": "Response", "method": "cookie", "vuln_class": "cookie_misconfig"},
    {"kind": "sink", "receiver_fqn": "session", "method": "session", "vuln_class": "cookie_misconfig"},
    {"kind": "sink", "receiver_fqn": "expressSession", "method": "<init>", "vuln_class": "cookie_misconfig"},
    {"kind": "sink", "receiver_fqn": "cookieSession", "method": "<init>", "vuln_class": "cookie_misconfig"}
  ]
}
```

- [ ] **Step 2: Validate + commit + push**

```
python3 -c "import json; json.load(open('internal/sast/engine/models/js-cookie.json'))" && echo OK
git add internal/sast/engine/models/js-cookie.json
git commit -m "feat(sast): add js-cookie framework model"
git push
```

### Task B.3: Create `java-cookie.json` framework model

**Files:**
- Create: `internal/sast/engine/models/java-cookie.json`

- [ ] **Step 1: Write the file**

```json
{
  "language": "java",
  "framework": "java-cookie",
  "models": [
    {"kind": "sink", "receiver_fqn": "javax.servlet.http.HttpServletResponse", "method": "addCookie", "vuln_class": "cookie_misconfig"},
    {"kind": "sink", "receiver_fqn": "jakarta.servlet.http.HttpServletResponse", "method": "addCookie", "vuln_class": "cookie_misconfig"},
    {"kind": "sink", "receiver_fqn": "javax.servlet.http.Cookie", "method": "setSecure", "vuln_class": "cookie_misconfig"},
    {"kind": "sink", "receiver_fqn": "javax.servlet.http.Cookie", "method": "setHttpOnly", "vuln_class": "cookie_misconfig"},
    {"kind": "sink", "receiver_fqn": "org.springframework.http.ResponseCookie.ResponseCookieBuilder", "method": "build", "vuln_class": "cookie_misconfig"},
    {"kind": "sink", "receiver_fqn": "ResponseCookie.ResponseCookieBuilder", "method": "build", "vuln_class": "cookie_misconfig"}
  ]
}
```

- [ ] **Step 2: Validate + commit + push**

```
python3 -c "import json; json.load(open('internal/sast/engine/models/java-cookie.json'))" && echo OK
git add internal/sast/engine/models/java-cookie.json
git commit -m "feat(sast): add java-cookie framework model"
git push
```

### Task B.4: Create `csharp-cookie.json` framework model

**Files:**
- Create: `internal/sast/engine/models/csharp-cookie.json`

- [ ] **Step 1: Write the file**

```json
{
  "language": "csharp",
  "framework": "csharp-cookie",
  "models": [
    {"kind": "sink", "receiver_fqn": "Microsoft.AspNetCore.Http.IResponseCookies", "method": "Append", "vuln_class": "cookie_misconfig"},
    {"kind": "sink", "receiver_fqn": "IResponseCookies", "method": "Append", "vuln_class": "cookie_misconfig"},
    {"kind": "sink", "receiver_fqn": "HttpResponse", "method": "Cookies.Append", "vuln_class": "cookie_misconfig"},
    {"kind": "sink", "receiver_fqn": "Response", "method": "Cookies.Append", "vuln_class": "cookie_misconfig"}
  ]
}
```

- [ ] **Step 2: Validate + commit + push**

```
python3 -c "import json; json.load(open('internal/sast/engine/models/csharp-cookie.json'))" && echo OK
git add internal/sast/engine/models/csharp-cookie.json
git commit -m "feat(sast): add csharp-cookie framework model"
git push
```

### Task B.5: SC-PY-COOKIE-001 (Missing Secure flag)

**Files:**
- Create: `internal/sast/rules/builtins/SC-PY-COOKIE-001.json`
- Create: `internal/sast/fixtures/python/cookie_positive.py`
- Create: `internal/sast/fixtures/python/cookie_negative.py`

- [ ] **Step 1: Write the rule**

```json
{
  "rule_id": "SC-PY-COOKIE-001",
  "name": "Cookie set without Secure flag",
  "language": "python",
  "cwe": ["CWE-614"],
  "owasp": ["A05:2021"],
  "severity": "medium",
  "confidence": { "base": 0.75 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "flask.Response",
        "callee": "set_cookie",
        "arg_index": 2,
        "arg_text_missing_any": ["secure", "Secure"],
        "message_template": "Flask set_cookie call without secure=True allows the cookie to be sent over plaintext HTTP"
      },
      {
        "receiver_fqn": "django.http.HttpResponse",
        "callee": "set_cookie",
        "arg_index": 2,
        "arg_text_missing_any": ["secure", "Secure"],
        "message_template": "Django set_cookie without secure=True"
      },
      {
        "receiver_fqn": "Response",
        "callee": "set_cookie",
        "arg_index": 2,
        "arg_text_missing_any": ["secure", "Secure"],
        "message_template": "Response.set_cookie without secure=True"
      },
      {
        "receiver_fqn": "response",
        "callee": "set_cookie",
        "arg_index": 2,
        "arg_text_missing_any": ["secure", "Secure"],
        "message_template": "response.set_cookie without secure=True"
      }
    ]
  },
  "description": "A response cookie is set without the Secure flag. Secure-less cookies are transmitted over plaintext HTTP, exposing session identifiers to network observers.",
  "remediation": "Pass secure=True to set_cookie. For Flask, also configure SESSION_COOKIE_SECURE=True. For Django, set SESSION_COOKIE_SECURE in settings.",
  "references": [
    "https://cwe.mitre.org/data/definitions/614.html",
    "https://owasp.org/www-community/controls/SecureCookieAttribute"
  ]
}
```

- [ ] **Step 2: Positive fixture**

```python
# internal/sast/fixtures/python/cookie_positive.py
from flask import Flask, Response

app = Flask(__name__)

@app.route("/login")
def login():
    resp = Response("ok")
    resp.set_cookie("session", "abc123", httponly=True, samesite="Lax")
    return resp
```

- [ ] **Step 3: Negative fixture**

```python
# internal/sast/fixtures/python/cookie_negative.py
from flask import Flask, Response

app = Flask(__name__)

@app.route("/login")
def login():
    resp = Response("ok")
    resp.set_cookie("session", "abc123", secure=True, httponly=True, samesite="Lax")
    return resp
```

- [ ] **Step 4: Verify rule loads**

```
go test ./internal/sast/rules/... -run TestLoadBuiltins -v 2>&1 | tail -10
```

- [ ] **Step 5: Commit + push**

```
git add internal/sast/rules/builtins/SC-PY-COOKIE-001.json internal/sast/fixtures/python/cookie_positive.py internal/sast/fixtures/python/cookie_negative.py
git commit -m "feat(sast): SC-PY-COOKIE-001 — Flask/Django cookie missing Secure"
git push
```

### Task B.6: SC-PY-COOKIE-002 (Missing HttpOnly)

**Files:**
- Create: `internal/sast/rules/builtins/SC-PY-COOKIE-002.json`

- [ ] **Step 1: Write the rule** (mirror B.5 with `httponly`/`HttpOnly` and CWE-1004)

```json
{
  "rule_id": "SC-PY-COOKIE-002",
  "name": "Cookie set without HttpOnly flag",
  "language": "python",
  "cwe": ["CWE-1004"],
  "owasp": ["A05:2021"],
  "severity": "medium",
  "confidence": { "base": 0.75 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "flask.Response",
        "callee": "set_cookie",
        "arg_index": 2,
        "arg_text_missing_any": ["httponly", "HttpOnly"],
        "message_template": "Flask set_cookie without httponly=True allows JS access to the cookie"
      },
      {
        "receiver_fqn": "django.http.HttpResponse",
        "callee": "set_cookie",
        "arg_index": 2,
        "arg_text_missing_any": ["httponly", "HttpOnly"],
        "message_template": "Django set_cookie without httponly=True"
      },
      {
        "receiver_fqn": "Response",
        "callee": "set_cookie",
        "arg_index": 2,
        "arg_text_missing_any": ["httponly", "HttpOnly"],
        "message_template": "Response.set_cookie without httponly=True"
      },
      {
        "receiver_fqn": "response",
        "callee": "set_cookie",
        "arg_index": 2,
        "arg_text_missing_any": ["httponly", "HttpOnly"],
        "message_template": "response.set_cookie without httponly=True"
      }
    ]
  },
  "description": "A response cookie is set without HttpOnly. HttpOnly-less cookies are accessible from document.cookie in JavaScript, expanding the impact of any XSS to session theft.",
  "remediation": "Pass httponly=True to set_cookie.",
  "references": ["https://cwe.mitre.org/data/definitions/1004.html"]
}
```

(Reuses cookie_positive.py + cookie_negative.py fixtures from B.5.)

- [ ] **Step 2: Commit + push**

```
git add internal/sast/rules/builtins/SC-PY-COOKIE-002.json
git commit -m "feat(sast): SC-PY-COOKIE-002 — Flask/Django cookie missing HttpOnly"
git push
```

### Task B.7: SC-PY-COOKIE-003 (Missing SameSite)

**Files:**
- Create: `internal/sast/rules/builtins/SC-PY-COOKIE-003.json`

- [ ] **Step 1: Write the rule**

```json
{
  "rule_id": "SC-PY-COOKIE-003",
  "name": "Cookie set without SameSite attribute",
  "language": "python",
  "cwe": ["CWE-1275"],
  "owasp": ["A05:2021"],
  "severity": "medium",
  "confidence": { "base": 0.70 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "flask.Response",
        "callee": "set_cookie",
        "arg_index": 2,
        "arg_text_missing_any": ["samesite", "SameSite"],
        "message_template": "Flask set_cookie without samesite= leaves CSRF protection to chance"
      },
      {
        "receiver_fqn": "django.http.HttpResponse",
        "callee": "set_cookie",
        "arg_index": 2,
        "arg_text_missing_any": ["samesite", "SameSite"],
        "message_template": "Django set_cookie without samesite="
      },
      {
        "receiver_fqn": "Response",
        "callee": "set_cookie",
        "arg_index": 2,
        "arg_text_missing_any": ["samesite", "SameSite"],
        "message_template": "Response.set_cookie without samesite="
      },
      {
        "receiver_fqn": "response",
        "callee": "set_cookie",
        "arg_index": 2,
        "arg_text_missing_any": ["samesite", "SameSite"],
        "message_template": "response.set_cookie without samesite="
      }
    ]
  },
  "description": "A response cookie is set without a SameSite attribute. Modern browsers default to Lax but legacy browsers default to None, leaving cross-origin requests able to attach the cookie.",
  "remediation": "Pass samesite=\"Lax\" or samesite=\"Strict\" to set_cookie.",
  "references": ["https://cwe.mitre.org/data/definitions/1275.html"]
}
```

- [ ] **Step 2: Commit + push**

```
git add internal/sast/rules/builtins/SC-PY-COOKIE-003.json
git commit -m "feat(sast): SC-PY-COOKIE-003 — Flask/Django cookie missing SameSite"
git push
```

### Task B.8: SC-JS-COOKIE-001/002/003

**Files:**
- Create: `internal/sast/rules/builtins/SC-JS-COOKIE-001.json`
- Create: `internal/sast/rules/builtins/SC-JS-COOKIE-002.json`
- Create: `internal/sast/rules/builtins/SC-JS-COOKIE-003.json`
- Create: `internal/sast/fixtures/javascript/cookie_positive.js`
- Create: `internal/sast/fixtures/javascript/cookie_negative.js`

- [ ] **Step 1: Write SC-JS-COOKIE-001 (Secure)**

```json
{
  "rule_id": "SC-JS-COOKIE-001",
  "name": "Cookie set without Secure flag",
  "language": "javascript",
  "cwe": ["CWE-614"],
  "owasp": ["A05:2021"],
  "severity": "medium",
  "confidence": { "base": 0.75 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "res",
        "callee": "cookie",
        "arg_index": 2,
        "arg_text_missing_any": ["secure", "Secure"],
        "message_template": "res.cookie() without secure: true"
      },
      {
        "receiver_fqn": "response",
        "callee": "cookie",
        "arg_index": 2,
        "arg_text_missing_any": ["secure", "Secure"],
        "message_template": "response.cookie() without secure: true"
      }
    ]
  },
  "description": "An Express response cookie is set without secure: true. Cookies without the Secure flag are sent over plaintext HTTP, leaking session tokens to passive network observers.",
  "remediation": "Set secure: true in the cookie options. In production, also enable cookie.secure on the express-session middleware.",
  "references": ["https://cwe.mitre.org/data/definitions/614.html"]
}
```

- [ ] **Step 2: Write SC-JS-COOKIE-002 (HttpOnly)**

```json
{
  "rule_id": "SC-JS-COOKIE-002",
  "name": "Cookie set without HttpOnly flag",
  "language": "javascript",
  "cwe": ["CWE-1004"],
  "owasp": ["A05:2021"],
  "severity": "medium",
  "confidence": { "base": 0.75 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "res",
        "callee": "cookie",
        "arg_index": 2,
        "arg_text_missing_any": ["httpOnly", "HttpOnly"],
        "message_template": "res.cookie() without httpOnly: true"
      },
      {
        "receiver_fqn": "response",
        "callee": "cookie",
        "arg_index": 2,
        "arg_text_missing_any": ["httpOnly", "HttpOnly"],
        "message_template": "response.cookie() without httpOnly: true"
      }
    ]
  },
  "description": "Cookie missing httpOnly: true is reachable from JavaScript via document.cookie, magnifying the impact of any XSS into session theft.",
  "remediation": "Set httpOnly: true in the cookie options object.",
  "references": ["https://cwe.mitre.org/data/definitions/1004.html"]
}
```

- [ ] **Step 3: Write SC-JS-COOKIE-003 (SameSite)**

```json
{
  "rule_id": "SC-JS-COOKIE-003",
  "name": "Cookie set without SameSite attribute",
  "language": "javascript",
  "cwe": ["CWE-1275"],
  "owasp": ["A05:2021"],
  "severity": "medium",
  "confidence": { "base": 0.70 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "res",
        "callee": "cookie",
        "arg_index": 2,
        "arg_text_missing_any": ["sameSite", "SameSite"],
        "message_template": "res.cookie() without sameSite attribute"
      },
      {
        "receiver_fqn": "response",
        "callee": "cookie",
        "arg_index": 2,
        "arg_text_missing_any": ["sameSite", "SameSite"],
        "message_template": "response.cookie() without sameSite attribute"
      }
    ]
  },
  "description": "Cookie missing sameSite leaves the browser to apply its default, which historically was None. This leaves the cookie attached to cross-origin requests.",
  "remediation": "Set sameSite: 'lax' or sameSite: 'strict' in the cookie options.",
  "references": ["https://cwe.mitre.org/data/definitions/1275.html"]
}
```

- [ ] **Step 4: Positive fixture**

```javascript
// internal/sast/fixtures/javascript/cookie_positive.js
const express = require("express");
const app = express();

app.post("/login", (req, res) => {
  res.cookie("session", "abc123", { httpOnly: true, sameSite: "lax" });
  res.send("ok");
});
```

- [ ] **Step 5: Negative fixture**

```javascript
// internal/sast/fixtures/javascript/cookie_negative.js
const express = require("express");
const app = express();

app.post("/login", (req, res) => {
  res.cookie("session", "abc123", { secure: true, httpOnly: true, sameSite: "lax" });
  res.send("ok");
});
```

- [ ] **Step 6: Commit + push**

```
git add internal/sast/rules/builtins/SC-JS-COOKIE-001.json internal/sast/rules/builtins/SC-JS-COOKIE-002.json internal/sast/rules/builtins/SC-JS-COOKIE-003.json internal/sast/fixtures/javascript/cookie_positive.js internal/sast/fixtures/javascript/cookie_negative.js
git commit -m "feat(sast): SC-JS-COOKIE-001/002/003 — Express cookie missing Secure/HttpOnly/SameSite"
git push
```

### Task B.9: SC-JAVA-COOKIE-001/002/003

**Files:**
- Create: `internal/sast/rules/builtins/SC-JAVA-COOKIE-001.json`
- Create: `internal/sast/rules/builtins/SC-JAVA-COOKIE-002.json`
- Create: `internal/sast/rules/builtins/SC-JAVA-COOKIE-003.json`
- Create: `internal/sast/fixtures/java/cookie_positive.java`
- Create: `internal/sast/fixtures/java/cookie_negative.java`

Java cookies are configured via separate setter calls on a `Cookie` object. The detection strategy is: fire when `addCookie` is called and the surrounding statement source does not contain `setSecure`, `setHttpOnly`, or `setSameSite`.

- [ ] **Step 1: Write SC-JAVA-COOKIE-001 (Secure)**

```json
{
  "rule_id": "SC-JAVA-COOKIE-001",
  "name": "Cookie added without setSecure(true)",
  "language": "java",
  "cwe": ["CWE-614"],
  "owasp": ["A05:2021"],
  "severity": "medium",
  "confidence": { "base": 0.65 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "javax.servlet.http.HttpServletResponse",
        "callee": "addCookie",
        "arg_index": 0,
        "arg_text_missing_any": ["setSecure(true)", ".secure(true)"],
        "message_template": "addCookie call without prior setSecure(true) — cookie may be sent over plain HTTP"
      },
      {
        "receiver_fqn": "jakarta.servlet.http.HttpServletResponse",
        "callee": "addCookie",
        "arg_index": 0,
        "arg_text_missing_any": ["setSecure(true)", ".secure(true)"],
        "message_template": "addCookie call without setSecure(true)"
      }
    ]
  },
  "description": "A servlet Cookie is added to the response without setSecure(true). The cookie will be transmitted over plaintext HTTP, leaking session identifiers to network observers.",
  "remediation": "Call cookie.setSecure(true) before response.addCookie(cookie). For Spring's ResponseCookie.builder, use .secure(true).",
  "references": ["https://cwe.mitre.org/data/definitions/614.html"]
}
```

Note: `arg_text_missing_any` here checks the source-text of the cookie variable expression — typically a single identifier like `cookie`. This works because the rule fires when the variable's source text doesn't reference setSecure. False-positives expected when setSecure is called in a far-away helper. Confidence kept at 0.65 to reflect this.

- [ ] **Step 2: Write SC-JAVA-COOKIE-002 (HttpOnly)** — mirror B.9 step 1 with `setHttpOnly(true)` and CWE-1004.

```json
{
  "rule_id": "SC-JAVA-COOKIE-002",
  "name": "Cookie added without setHttpOnly(true)",
  "language": "java",
  "cwe": ["CWE-1004"],
  "owasp": ["A05:2021"],
  "severity": "medium",
  "confidence": { "base": 0.65 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "javax.servlet.http.HttpServletResponse",
        "callee": "addCookie",
        "arg_index": 0,
        "arg_text_missing_any": ["setHttpOnly(true)", ".httpOnly(true)"],
        "message_template": "addCookie call without setHttpOnly(true)"
      },
      {
        "receiver_fqn": "jakarta.servlet.http.HttpServletResponse",
        "callee": "addCookie",
        "arg_index": 0,
        "arg_text_missing_any": ["setHttpOnly(true)", ".httpOnly(true)"],
        "message_template": "addCookie call without setHttpOnly(true)"
      }
    ]
  },
  "description": "Servlet Cookie added without setHttpOnly(true), exposing the cookie value to any DOM-XSS in the application.",
  "remediation": "Call cookie.setHttpOnly(true) before response.addCookie(cookie).",
  "references": ["https://cwe.mitre.org/data/definitions/1004.html"]
}
```

- [ ] **Step 3: Write SC-JAVA-COOKIE-003 (SameSite)**

Java servlet `Cookie` does not expose SameSite as a setter until very recent versions; SameSite is typically set via response header. Detect both: cookie variable lacking `setAttribute("SameSite"` or any explicit SameSite mention.

```json
{
  "rule_id": "SC-JAVA-COOKIE-003",
  "name": "Cookie added without SameSite attribute",
  "language": "java",
  "cwe": ["CWE-1275"],
  "owasp": ["A05:2021"],
  "severity": "low",
  "confidence": { "base": 0.55 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "javax.servlet.http.HttpServletResponse",
        "callee": "addCookie",
        "arg_index": 0,
        "arg_text_missing_any": ["SameSite", "sameSite"],
        "message_template": "addCookie without explicit SameSite attribute"
      }
    ]
  },
  "description": "Cookie added without SameSite attribute. Older browsers default to None, leaving the cookie attached to cross-origin requests.",
  "remediation": "Use Spring's ResponseCookie.builder with .sameSite(\"Lax\") or set the SameSite header explicitly.",
  "references": ["https://cwe.mitre.org/data/definitions/1275.html"]
}
```

- [ ] **Step 4: Positive fixture**

```java
// internal/sast/fixtures/java/cookie_positive.java
import javax.servlet.http.*;
import java.io.IOException;

public class CookiePositive extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Cookie cookie = new Cookie("session", "abc123");
        resp.addCookie(cookie);
    }
}
```

- [ ] **Step 5: Negative fixture**

```java
// internal/sast/fixtures/java/cookie_negative.java
import javax.servlet.http.*;
import java.io.IOException;

public class CookieNegative extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Cookie cookie = new Cookie("session", "abc123");
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setAttribute("SameSite", "Lax");
        resp.addCookie(cookie);
    }
}
```

- [ ] **Step 6: Commit + push**

```
git add internal/sast/rules/builtins/SC-JAVA-COOKIE-001.json internal/sast/rules/builtins/SC-JAVA-COOKIE-002.json internal/sast/rules/builtins/SC-JAVA-COOKIE-003.json internal/sast/fixtures/java/cookie_positive.java internal/sast/fixtures/java/cookie_negative.java
git commit -m "feat(sast): SC-JAVA-COOKIE-001/002/003 — servlet cookie missing setSecure/HttpOnly/SameSite"
git push
```

### Task B.10: SC-CSHARP-COOKIE-001/002/003

**Files:**
- Create: `internal/sast/rules/builtins/SC-CSHARP-COOKIE-001.json`
- Create: `internal/sast/rules/builtins/SC-CSHARP-COOKIE-002.json`
- Create: `internal/sast/rules/builtins/SC-CSHARP-COOKIE-003.json`
- Create: `internal/sast/fixtures/csharp/Cookie_positive.cs`
- Create: `internal/sast/fixtures/csharp/Cookie_negative.cs`

ASP.NET uses `CookieOptions` initializer object — same options-text pattern as JS.

- [ ] **Step 1: Write SC-CSHARP-COOKIE-001 (Secure)**

```json
{
  "rule_id": "SC-CSHARP-COOKIE-001",
  "name": "Cookie appended without Secure flag",
  "language": "csharp",
  "cwe": ["CWE-614"],
  "owasp": ["A05:2021"],
  "severity": "medium",
  "confidence": { "base": 0.75 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "Microsoft.AspNetCore.Http.IResponseCookies",
        "callee": "Append",
        "arg_index": 2,
        "arg_text_missing_any": ["Secure"],
        "message_template": "IResponseCookies.Append called with CookieOptions missing Secure"
      },
      {
        "receiver_fqn": "IResponseCookies",
        "callee": "Append",
        "arg_index": 2,
        "arg_text_missing_any": ["Secure"],
        "message_template": "IResponseCookies.Append missing Secure"
      }
    ]
  },
  "description": "Response cookie appended without CookieOptions.Secure = true. ASP.NET defaults Secure to false outside of a HTTPS-only environment.",
  "remediation": "Set Secure = true on the CookieOptions initializer.",
  "references": ["https://cwe.mitre.org/data/definitions/614.html"]
}
```

- [ ] **Step 2: Write SC-CSHARP-COOKIE-002 (HttpOnly)**

```json
{
  "rule_id": "SC-CSHARP-COOKIE-002",
  "name": "Cookie appended without HttpOnly flag",
  "language": "csharp",
  "cwe": ["CWE-1004"],
  "owasp": ["A05:2021"],
  "severity": "medium",
  "confidence": { "base": 0.75 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "Microsoft.AspNetCore.Http.IResponseCookies",
        "callee": "Append",
        "arg_index": 2,
        "arg_text_missing_any": ["HttpOnly"],
        "message_template": "IResponseCookies.Append called with CookieOptions missing HttpOnly"
      },
      {
        "receiver_fqn": "IResponseCookies",
        "callee": "Append",
        "arg_index": 2,
        "arg_text_missing_any": ["HttpOnly"],
        "message_template": "IResponseCookies.Append missing HttpOnly"
      }
    ]
  },
  "description": "Cookie appended without CookieOptions.HttpOnly = true.",
  "remediation": "Set HttpOnly = true on the CookieOptions initializer.",
  "references": ["https://cwe.mitre.org/data/definitions/1004.html"]
}
```

- [ ] **Step 3: Write SC-CSHARP-COOKIE-003 (SameSite)**

```json
{
  "rule_id": "SC-CSHARP-COOKIE-003",
  "name": "Cookie appended without SameSite attribute",
  "language": "csharp",
  "cwe": ["CWE-1275"],
  "owasp": ["A05:2021"],
  "severity": "medium",
  "confidence": { "base": 0.70 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "Microsoft.AspNetCore.Http.IResponseCookies",
        "callee": "Append",
        "arg_index": 2,
        "arg_text_missing_any": ["SameSite"],
        "message_template": "IResponseCookies.Append missing SameSite"
      },
      {
        "receiver_fqn": "IResponseCookies",
        "callee": "Append",
        "arg_index": 2,
        "arg_text_missing_any": ["SameSite"],
        "message_template": "IResponseCookies.Append missing SameSite"
      }
    ]
  },
  "description": "Cookie appended without CookieOptions.SameSite set.",
  "remediation": "Set SameSite = SameSiteMode.Lax (or Strict) on the CookieOptions initializer.",
  "references": ["https://cwe.mitre.org/data/definitions/1275.html"]
}
```

- [ ] **Step 4: Positive fixture**

```csharp
// internal/sast/fixtures/csharp/Cookie_positive.cs
using Microsoft.AspNetCore.Mvc;

public class CookieController : Controller
{
    public IActionResult Login()
    {
        Response.Cookies.Append("session", "abc123", new CookieOptions { });
        return Ok();
    }
}
```

- [ ] **Step 5: Negative fixture**

```csharp
// internal/sast/fixtures/csharp/Cookie_negative.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;

public class CookieNegativeController : Controller
{
    public IActionResult Login()
    {
        Response.Cookies.Append("session", "abc123", new CookieOptions
        {
            Secure = true,
            HttpOnly = true,
            SameSite = SameSiteMode.Lax
        });
        return Ok();
    }
}
```

- [ ] **Step 6: Commit + push**

```
git add internal/sast/rules/builtins/SC-CSHARP-COOKIE-001.json internal/sast/rules/builtins/SC-CSHARP-COOKIE-002.json internal/sast/rules/builtins/SC-CSHARP-COOKIE-003.json internal/sast/fixtures/csharp/Cookie_positive.cs internal/sast/fixtures/csharp/Cookie_negative.cs
git commit -m "feat(sast): SC-CSHARP-COOKIE-001/002/003 — ASP.NET cookie missing Secure/HttpOnly/SameSite"
git push
```

### Task B.11: Update loader test for cookie rules

**Files:**
- Modify: `internal/sast/rules/loader_test.go`

- [ ] **Step 1: Append a new test function**

```go
func TestLoadBuiltins_CookieRulesPR(t *testing.T) {
	rs, err := LoadBuiltins()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	idIndex := make(map[string]*Rule, len(rs))
	for _, r := range rs {
		idIndex[r.RuleID] = r
	}
	expected := []string{
		"SC-PY-COOKIE-001", "SC-PY-COOKIE-002", "SC-PY-COOKIE-003",
		"SC-JS-COOKIE-001", "SC-JS-COOKIE-002", "SC-JS-COOKIE-003",
		"SC-JAVA-COOKIE-001", "SC-JAVA-COOKIE-002", "SC-JAVA-COOKIE-003",
		"SC-CSHARP-COOKIE-001", "SC-CSHARP-COOKIE-002", "SC-CSHARP-COOKIE-003",
	}
	for _, id := range expected {
		t.Run(id, func(t *testing.T) {
			r, ok := idIndex[id]
			if !ok {
				t.Fatalf("rule %s missing", id)
			}
			if r.Severity == "" {
				t.Errorf("severity empty")
			}
			if r.Description == "" {
				t.Errorf("description empty")
			}
			if r.Remediation == "" {
				t.Errorf("remediation empty")
			}
			if r.Detection.Kind != DetectionASTCall {
				t.Errorf("expected ast_call, got %q", r.Detection.Kind)
			}
		})
	}
}
```

- [ ] **Step 2: Run the test**

```
go test ./internal/sast/rules/... -run TestLoadBuiltins_CookieRulesPR -v 2>&1 | tail -25
```

Expected: PASS, 12 sub-tests.

- [ ] **Step 3: Commit + push**

```
git add internal/sast/rules/loader_test.go
git commit -m "test(sast): cover cookie rules from PR B in loader test"
git push
```

### Task B.12: PR B build, deploy, smoke

- [ ] **Step 1: Run all SAST tests**

```
cd /Users/okyay/Documents/SentinelCore/.worktrees/auth-rules
go test ./internal/sast/...
```

Expected: PASS for every package.

- [ ] **Step 2: Sync, build, deploy** (mirrors A.12 with `auth-prb` tag)

```
rsync -az --delete --exclude .git --exclude '*.test' \
  internal/ migrations/ pkg/ rules/ scripts/ Dockerfile go.mod go.sum cmd/ \
  okyay@77.42.34.174:/tmp/sentinelcore-src/
ssh okyay@77.42.34.174 "cd /tmp/sentinelcore-src && \
  docker build -t sentinelcore/controlplane:auth-prb . 2>&1 | tail -5 && \
  docker build -f cmd/sast-worker/Dockerfile -t sentinelcore/sast-worker:auth-prb . 2>&1 | tail -5 && \
  docker tag sentinelcore/controlplane:auth-prb sentinelcore/controlplane:pilot && \
  docker tag sentinelcore/sast-worker:auth-prb sentinelcore/sast-worker:pilot && \
  cd /opt/sentinelcore/compose && docker compose up -d controlplane sast_worker"
curl -s -o /dev/null -w 'healthz: %{http_code}\nreadyz: %{http_code}\n' \
  https://sentinelcore.resiliencetech.com.tr/healthz
curl -s -o /dev/null -w 'readyz: %{http_code}\n' \
  https://sentinelcore.resiliencetech.com.tr/readyz
```

Expected: both 200.

PR B is complete. 12 cookie rules deployed; 64 → 76 total rules.

---

## PR C — JWT, session, auth-header rules (21 rules)

### Task C.1: Create JWT framework models (4 files)

**Files:**
- Create: `internal/sast/engine/models/python-jwt.json`
- Create: `internal/sast/engine/models/js-jwt.json`
- Create: `internal/sast/engine/models/java-jwt.json`
- Create: `internal/sast/engine/models/csharp-jwt.json`

- [ ] **Step 1: Write python-jwt.json**

```json
{
  "language": "python",
  "framework": "python-jwt",
  "models": [
    {"kind": "sink", "receiver_fqn": "jwt", "method": "decode", "vuln_class": "jwt_unverified"},
    {"kind": "sink", "receiver_fqn": "jwt", "method": "decode", "vuln_class": "jwt_weak_alg"},
    {"kind": "sink", "receiver_fqn": "PyJWT", "method": "decode", "vuln_class": "jwt_unverified"}
  ]
}
```

- [ ] **Step 2: Write js-jwt.json**

```json
{
  "language": "javascript",
  "framework": "js-jwt",
  "models": [
    {"kind": "sink", "receiver_fqn": "jwt", "method": "verify", "vuln_class": "jwt_weak_alg"},
    {"kind": "sink", "receiver_fqn": "jwt", "method": "decode", "vuln_class": "jwt_unverified"},
    {"kind": "sink", "receiver_fqn": "jsonwebtoken", "method": "verify", "vuln_class": "jwt_weak_alg"},
    {"kind": "sink", "receiver_fqn": "jsonwebtoken", "method": "decode", "vuln_class": "jwt_unverified"}
  ]
}
```

- [ ] **Step 3: Write java-jwt.json**

```json
{
  "language": "java",
  "framework": "java-jwt",
  "models": [
    {"kind": "sink", "receiver_fqn": "io.jsonwebtoken.JwtParser", "method": "parse", "vuln_class": "jwt_unverified"},
    {"kind": "sink", "receiver_fqn": "io.jsonwebtoken.Jwts", "method": "parser", "vuln_class": "jwt_unverified"},
    {"kind": "sink", "receiver_fqn": "io.jsonwebtoken.JwtParser", "method": "parseClaimsJwt", "vuln_class": "jwt_unverified"}
  ]
}
```

- [ ] **Step 4: Write csharp-jwt.json**

```json
{
  "language": "csharp",
  "framework": "csharp-jwt",
  "models": [
    {"kind": "sink", "receiver_fqn": "System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler", "method": "ReadJwtToken", "vuln_class": "jwt_unverified"},
    {"kind": "sink", "receiver_fqn": "JwtSecurityTokenHandler", "method": "ReadJwtToken", "vuln_class": "jwt_unverified"}
  ]
}
```

- [ ] **Step 5: Validate, commit, push**

```
for f in python-jwt.json js-jwt.json java-jwt.json csharp-jwt.json; do
  python3 -c "import json; json.load(open('internal/sast/engine/models/$f'))" && echo "$f OK"
done
git add internal/sast/engine/models/python-jwt.json internal/sast/engine/models/js-jwt.json internal/sast/engine/models/java-jwt.json internal/sast/engine/models/csharp-jwt.json
git commit -m "feat(sast): add jwt framework models for 4 languages"
git push
```

### Task C.2: SC-PY-JWT-001 / 002 / 003

**Files:**
- Create: `internal/sast/rules/builtins/SC-PY-JWT-001.json`
- Create: `internal/sast/rules/builtins/SC-PY-JWT-002.json`
- Create: `internal/sast/rules/builtins/SC-PY-JWT-003.json`
- Create: `internal/sast/fixtures/python/jwt_positive.py`
- Create: `internal/sast/fixtures/python/jwt_negative.py`

- [ ] **Step 1: SC-PY-JWT-001 (verify=False)**

```json
{
  "rule_id": "SC-PY-JWT-001",
  "name": "JWT decoded without signature verification",
  "language": "python",
  "cwe": ["CWE-347"],
  "owasp": ["A02:2021"],
  "severity": "critical",
  "confidence": { "base": 0.85 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "jwt",
        "callee": "decode",
        "arg_index": 2,
        "arg_text_contains_any": ["verify_signature\": False", "verify_signature\":False", "verify_signature=False"],
        "message_template": "jwt.decode called with verify_signature disabled"
      },
      {
        "receiver_fqn": "jwt",
        "callee": "decode",
        "arg_index": 2,
        "arg_text_contains_any": ["verify\": False", "verify=False"],
        "message_template": "jwt.decode called with verify=False (legacy PyJWT option)"
      }
    ]
  },
  "description": "PyJWT decode is invoked with signature verification disabled. Any attacker-supplied token is accepted unconditionally — this is equivalent to having no authentication at all on whatever uses the resulting claims.",
  "remediation": "Always pass options={\"verify_signature\": True} (default) and supply the correct algorithms list. Never use verify=False except in test code.",
  "references": ["https://cwe.mitre.org/data/definitions/347.html"]
}
```

- [ ] **Step 2: SC-PY-JWT-002 (alg=none)**

```json
{
  "rule_id": "SC-PY-JWT-002",
  "name": "JWT accepts alg=none",
  "language": "python",
  "cwe": ["CWE-327"],
  "owasp": ["A02:2021"],
  "severity": "critical",
  "confidence": { "base": 0.90 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "jwt",
        "callee": "decode",
        "arg_index": 2,
        "arg_text_contains_any": ["\"none\"", "'none'", "algorithms=[\"none\"]", "algorithms=['none']"],
        "message_template": "jwt.decode allows alg=none — any unsigned token will be accepted"
      }
    ]
  },
  "description": "PyJWT is configured to accept the unsigned 'none' algorithm. An attacker can forge tokens with empty signatures.",
  "remediation": "Use a fixed algorithms allowlist that only contains your real signing algorithm: algorithms=[\"HS256\"] or algorithms=[\"RS256\"].",
  "references": ["https://cwe.mitre.org/data/definitions/327.html"]
}
```

- [ ] **Step 3: SC-PY-JWT-003 (hardcoded JWT secret)**

```json
{
  "rule_id": "SC-PY-JWT-003",
  "name": "Hardcoded JWT signing secret",
  "language": "python",
  "cwe": ["CWE-798"],
  "owasp": ["A07:2021"],
  "severity": "high",
  "confidence": { "base": 0.80 },
  "detection": {
    "kind": "ast_assign",
    "assign_patterns": [
      {
        "name_matches_any": ["(?i)jwt[_-]?secret", "(?i)jwt[_-]?key", "(?i)jwt[_-]?signing"],
        "min_value_length": 8,
        "exclude_values": ["(?i)^(test|change[-_]?me|placeholder|example|<.*>)$"],
        "require_entropy": false,
        "message_template": "Hardcoded JWT signing secret in source"
      }
    ]
  },
  "description": "A variable named like a JWT signing secret is assigned a string literal. Anyone with read access to the repository can forge tokens.",
  "remediation": "Load the secret from an environment variable, secret manager, or KMS at runtime.",
  "references": ["https://cwe.mitre.org/data/definitions/798.html"]
}
```

- [ ] **Step 4: Positive fixture**

```python
# internal/sast/fixtures/python/jwt_positive.py
import jwt

JWT_SECRET = "supersecretpassword12345"  # SC-PY-JWT-003

def verify_token_unsafe(token):
    return jwt.decode(token, JWT_SECRET, options={"verify_signature": False})  # SC-PY-JWT-001

def verify_token_alg_none(token):
    return jwt.decode(token, JWT_SECRET, algorithms=["none"])  # SC-PY-JWT-002
```

- [ ] **Step 5: Negative fixture**

```python
# internal/sast/fixtures/python/jwt_negative.py
import jwt
import os

JWT_SECRET = os.environ["JWT_SECRET"]

def verify_token(token):
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
```

- [ ] **Step 6: Commit + push**

```
git add internal/sast/rules/builtins/SC-PY-JWT-001.json internal/sast/rules/builtins/SC-PY-JWT-002.json internal/sast/rules/builtins/SC-PY-JWT-003.json internal/sast/fixtures/python/jwt_positive.py internal/sast/fixtures/python/jwt_negative.py
git commit -m "feat(sast): SC-PY-JWT-001/002/003 — pyjwt unverified/alg-none/hardcoded-secret"
git push
```

### Task C.3: SC-JS-JWT-001 / 002 / 003

**Files:** mirror C.2 for JS.
- Create: `internal/sast/rules/builtins/SC-JS-JWT-{001,002,003}.json`
- Create: `internal/sast/fixtures/javascript/jwt_{positive,negative}.js`

- [ ] **Step 1: SC-JS-JWT-001 (decode without verify)**

```json
{
  "rule_id": "SC-JS-JWT-001",
  "name": "JWT decoded without signature verification",
  "language": "javascript",
  "cwe": ["CWE-347"],
  "owasp": ["A02:2021"],
  "severity": "critical",
  "confidence": { "base": 0.85 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "jwt",
        "callee": "decode",
        "message_template": "jsonwebtoken.decode does NOT verify the signature — use jwt.verify"
      },
      {
        "receiver_fqn": "jsonwebtoken",
        "callee": "decode",
        "message_template": "jsonwebtoken.decode does NOT verify the signature"
      }
    ]
  },
  "description": "jsonwebtoken.decode parses a JWT without verifying the signature. Any token-shaped string is accepted, including attacker-crafted ones.",
  "remediation": "Use jwt.verify(token, secret, { algorithms: ['HS256'] }) instead of jwt.decode for any token coming from a client.",
  "references": ["https://cwe.mitre.org/data/definitions/347.html"]
}
```

- [ ] **Step 2: SC-JS-JWT-002 (alg=none / algorithms includes 'none')**

```json
{
  "rule_id": "SC-JS-JWT-002",
  "name": "JWT verify accepts alg=none",
  "language": "javascript",
  "cwe": ["CWE-327"],
  "owasp": ["A02:2021"],
  "severity": "critical",
  "confidence": { "base": 0.90 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "jwt",
        "callee": "verify",
        "arg_index": 2,
        "arg_text_contains_any": ["'none'", "\"none\""],
        "message_template": "jwt.verify accepts alg=none"
      },
      {
        "receiver_fqn": "jsonwebtoken",
        "callee": "verify",
        "arg_index": 2,
        "arg_text_contains_any": ["'none'", "\"none\""],
        "message_template": "jsonwebtoken.verify accepts alg=none"
      }
    ]
  },
  "description": "jsonwebtoken.verify is configured to accept the unsigned 'none' algorithm. Any attacker can produce a token that passes verification.",
  "remediation": "Pass algorithms: ['HS256'] (or whatever your real algorithm is) — never include 'none'.",
  "references": ["https://cwe.mitre.org/data/definitions/327.html"]
}
```

- [ ] **Step 3: SC-JS-JWT-003 (hardcoded secret)**

```json
{
  "rule_id": "SC-JS-JWT-003",
  "name": "Hardcoded JWT signing secret",
  "language": "javascript",
  "cwe": ["CWE-798"],
  "owasp": ["A07:2021"],
  "severity": "high",
  "confidence": { "base": 0.80 },
  "detection": {
    "kind": "ast_assign",
    "assign_patterns": [
      {
        "name_matches_any": ["(?i)jwt[_-]?secret", "(?i)jwt[_-]?key", "(?i)jwt[_-]?signing"],
        "min_value_length": 8,
        "exclude_values": ["(?i)^(test|change[-_]?me|placeholder|example|<.*>)$"],
        "require_entropy": false,
        "message_template": "Hardcoded JWT signing secret in source"
      }
    ]
  },
  "description": "Variable named like a JWT signing secret is assigned a string literal.",
  "remediation": "Load from environment variable or secret manager.",
  "references": ["https://cwe.mitre.org/data/definitions/798.html"]
}
```

- [ ] **Step 4: Positive fixture**

```javascript
// internal/sast/fixtures/javascript/jwt_positive.js
const jwt = require("jsonwebtoken");
const JWT_SECRET = "supersecretpassword12345"; // SC-JS-JWT-003

function decodeUnsafe(token) {
  return jwt.decode(token); // SC-JS-JWT-001
}

function verifyAllowsNone(token) {
  return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'none'] }); // SC-JS-JWT-002
}
```

- [ ] **Step 5: Negative fixture**

```javascript
// internal/sast/fixtures/javascript/jwt_negative.js
const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;

function verifySafe(token) {
  return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
}
```

- [ ] **Step 6: Commit + push**

```
git add internal/sast/rules/builtins/SC-JS-JWT-001.json internal/sast/rules/builtins/SC-JS-JWT-002.json internal/sast/rules/builtins/SC-JS-JWT-003.json internal/sast/fixtures/javascript/jwt_positive.js internal/sast/fixtures/javascript/jwt_negative.js
git commit -m "feat(sast): SC-JS-JWT-001/002/003 — jsonwebtoken unverified/alg-none/hardcoded-secret"
git push
```

### Task C.4: SC-JAVA-JWT-001 / 002 / 003

**Files:**
- Create: `internal/sast/rules/builtins/SC-JAVA-JWT-{001,002,003}.json`
- Create: `internal/sast/fixtures/java/Jwt_positive.java`
- Create: `internal/sast/fixtures/java/Jwt_negative.java`

- [ ] **Step 1: SC-JAVA-JWT-001 (parseClaimsJwt — unsigned)**

```json
{
  "rule_id": "SC-JAVA-JWT-001",
  "name": "JWT parsed without signature verification (parseClaimsJwt)",
  "language": "java",
  "cwe": ["CWE-347"],
  "owasp": ["A02:2021"],
  "severity": "critical",
  "confidence": { "base": 0.85 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "io.jsonwebtoken.JwtParser",
        "callee": "parseClaimsJwt",
        "message_template": "JwtParser.parseClaimsJwt does NOT verify signatures — use parseClaimsJws"
      },
      {
        "receiver_fqn": "JwtParser",
        "callee": "parseClaimsJwt",
        "message_template": "JwtParser.parseClaimsJwt does NOT verify signatures"
      }
    ]
  },
  "description": "jjwt's parseClaimsJwt method parses an unsigned JWT. Any token-shaped string passes; an attacker can forge claims at will.",
  "remediation": "Use parseClaimsJws (note the 's') with a configured signing key. parseClaimsJwt is for unsigned tokens only.",
  "references": ["https://cwe.mitre.org/data/definitions/347.html"]
}
```

- [ ] **Step 2: SC-JAVA-JWT-002 (alg=none allowed)**

```json
{
  "rule_id": "SC-JAVA-JWT-002",
  "name": "JWT verifier accepts alg=none",
  "language": "java",
  "cwe": ["CWE-327"],
  "owasp": ["A02:2021"],
  "severity": "critical",
  "confidence": { "base": 0.85 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "io.jsonwebtoken.JwtParser",
        "callee": "parse",
        "arg_index": 0,
        "arg_text_contains_any": ["SignatureAlgorithm.NONE", "\"none\""],
        "message_template": "jjwt parser configured for SignatureAlgorithm.NONE"
      }
    ]
  },
  "description": "jjwt parser is configured to accept tokens with alg=none.",
  "remediation": "Configure SignatureAlgorithm.HS256 (or the real algorithm) explicitly; never NONE.",
  "references": ["https://cwe.mitre.org/data/definitions/327.html"]
}
```

- [ ] **Step 3: SC-JAVA-JWT-003 (hardcoded secret)**

```json
{
  "rule_id": "SC-JAVA-JWT-003",
  "name": "Hardcoded JWT signing secret",
  "language": "java",
  "cwe": ["CWE-798"],
  "owasp": ["A07:2021"],
  "severity": "high",
  "confidence": { "base": 0.80 },
  "detection": {
    "kind": "ast_assign",
    "assign_patterns": [
      {
        "name_matches_any": ["(?i)jwt[_-]?secret", "(?i)jwt[_-]?key", "(?i)signing[_-]?key"],
        "min_value_length": 8,
        "exclude_values": ["(?i)^(test|change[-_]?me|placeholder|example|<.*>)$"],
        "require_entropy": false,
        "message_template": "Hardcoded JWT signing secret"
      }
    ]
  },
  "description": "Variable named like a JWT signing secret is assigned a string literal.",
  "remediation": "Read from environment via System.getenv() or a secret manager.",
  "references": ["https://cwe.mitre.org/data/definitions/798.html"]
}
```

- [ ] **Step 4: Positive fixture**

```java
// internal/sast/fixtures/java/Jwt_positive.java
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtPositive {
    private static final String JWT_SECRET = "supersecretpassword12345"; // SC-JAVA-JWT-003

    public Object decodeUnsigned(String token) {
        return Jwts.parser().parseClaimsJwt(token); // SC-JAVA-JWT-001
    }

    public Object decodeAllowsNone(String token) {
        return Jwts.parser().setSigningKey(JWT_SECRET).parse(token, SignatureAlgorithm.NONE); // SC-JAVA-JWT-002
    }
}
```

- [ ] **Step 5: Negative fixture**

```java
// internal/sast/fixtures/java/Jwt_negative.java
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;

public class JwtNegative {
    private final String secret = System.getenv("JWT_SECRET");

    public Claims verify(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }
}
```

- [ ] **Step 6: Commit + push**

```
git add internal/sast/rules/builtins/SC-JAVA-JWT-001.json internal/sast/rules/builtins/SC-JAVA-JWT-002.json internal/sast/rules/builtins/SC-JAVA-JWT-003.json internal/sast/fixtures/java/Jwt_positive.java internal/sast/fixtures/java/Jwt_negative.java
git commit -m "feat(sast): SC-JAVA-JWT-001/002/003 — jjwt unverified/alg-none/hardcoded-secret"
git push
```

### Task C.5: SC-CSHARP-JWT-001 / 002 / 003

**Files:** mirror C.4 for C#.

- [ ] **Step 1: SC-CSHARP-JWT-001 (ReadJwtToken — no validation)**

```json
{
  "rule_id": "SC-CSHARP-JWT-001",
  "name": "JWT read without signature validation (ReadJwtToken)",
  "language": "csharp",
  "cwe": ["CWE-347"],
  "owasp": ["A02:2021"],
  "severity": "critical",
  "confidence": { "base": 0.85 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler",
        "callee": "ReadJwtToken",
        "message_template": "ReadJwtToken parses without validating — use ValidateToken"
      },
      {
        "receiver_fqn": "JwtSecurityTokenHandler",
        "callee": "ReadJwtToken",
        "message_template": "ReadJwtToken parses without validating"
      }
    ]
  },
  "description": "JwtSecurityTokenHandler.ReadJwtToken parses a token but performs no signature validation.",
  "remediation": "Use ValidateToken with a configured TokenValidationParameters (IssuerSigningKey, ValidIssuer, ValidAudience).",
  "references": ["https://cwe.mitre.org/data/definitions/347.html"]
}
```

- [ ] **Step 2: SC-CSHARP-JWT-002 (TokenValidationParameters with ValidateSignature = false)**

```json
{
  "rule_id": "SC-CSHARP-JWT-002",
  "name": "TokenValidationParameters disables signature validation",
  "language": "csharp",
  "cwe": ["CWE-347"],
  "owasp": ["A02:2021"],
  "severity": "critical",
  "confidence": { "base": 0.85 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "JwtSecurityTokenHandler",
        "callee": "ValidateToken",
        "arg_index": 1,
        "arg_text_contains_any": ["ValidateSignature = false", "ValidateLifetime = false", "RequireSignedTokens = false"],
        "message_template": "ValidateToken called with validation disabled"
      }
    ]
  },
  "description": "TokenValidationParameters explicitly disables signature/lifetime validation.",
  "remediation": "Remove the disable; ValidateSignature and RequireSignedTokens must be true.",
  "references": ["https://cwe.mitre.org/data/definitions/347.html"]
}
```

- [ ] **Step 3: SC-CSHARP-JWT-003 (hardcoded secret)**

```json
{
  "rule_id": "SC-CSHARP-JWT-003",
  "name": "Hardcoded JWT signing secret",
  "language": "csharp",
  "cwe": ["CWE-798"],
  "owasp": ["A07:2021"],
  "severity": "high",
  "confidence": { "base": 0.80 },
  "detection": {
    "kind": "ast_assign",
    "assign_patterns": [
      {
        "name_matches_any": ["(?i)jwt[_-]?secret", "(?i)jwt[_-]?key", "(?i)signing[_-]?key", "(?i)issuerSigningKey"],
        "min_value_length": 8,
        "exclude_values": ["(?i)^(test|change[-_]?me|placeholder|example|<.*>)$"],
        "require_entropy": false,
        "message_template": "Hardcoded JWT signing secret"
      }
    ]
  },
  "description": "Variable named like a JWT signing secret is assigned a string literal.",
  "remediation": "Load from configuration provider (appsettings + Azure Key Vault, env var, or DPAPI).",
  "references": ["https://cwe.mitre.org/data/definitions/798.html"]
}
```

- [ ] **Step 4: Positive fixture**

```csharp
// internal/sast/fixtures/csharp/Jwt_positive.cs
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

public class JwtPositive
{
    private static readonly string JwtSecret = "supersecretpassword12345"; // SC-CSHARP-JWT-003

    public JwtSecurityToken ReadUnsigned(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        return handler.ReadJwtToken(token); // SC-CSHARP-JWT-001
    }

    public void DisableValidation(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        var p = new TokenValidationParameters
        {
            ValidateSignature = false,
            ValidateLifetime = false,
        };
        handler.ValidateToken(token, p, out _); // SC-CSHARP-JWT-002
    }
}
```

- [ ] **Step 5: Negative fixture**

```csharp
// internal/sast/fixtures/csharp/Jwt_negative.cs
using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;

public class JwtNegative
{
    public void Validate(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("JWT_SECRET"));
        var p = new TokenValidationParameters
        {
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            RequireSignedTokens = true,
        };
        handler.ValidateToken(token, p, out _);
    }
}
```

- [ ] **Step 6: Commit + push**

```
git add internal/sast/rules/builtins/SC-CSHARP-JWT-001.json internal/sast/rules/builtins/SC-CSHARP-JWT-002.json internal/sast/rules/builtins/SC-CSHARP-JWT-003.json internal/sast/fixtures/csharp/Jwt_positive.cs internal/sast/fixtures/csharp/Jwt_negative.cs
git commit -m "feat(sast): SC-CSHARP-JWT-001/002/003 — System.IdentityModel unverified/disabled/hardcoded-secret"
git push
```

### Task C.6: SC-JS-SESSION-001 (predictable session ID)

**Files:**
- Create: `internal/sast/rules/builtins/SC-JS-SESSION-001.json`
- Create: `internal/sast/fixtures/javascript/session_positive.js`
- Create: `internal/sast/fixtures/javascript/session_negative.js`

- [ ] **Step 1: Write the rule**

The detection strategy: fire on Math.random calls whose enclosing statement source contains "session", "sessionId", or "sessionID". This uses `arg_text_contains_any` against an enclosing-source span attached to the call instruction. Since `ArgSourceText` is per-operand and Math.random has no operands, we use the `MessageTemplate` against the receiver — a more precise approach is to add the rule against `req.session.id = ...` assignment, but our IR doesn't surface property assignment patterns easily.

**Fallback strategy:** match `Math.random` calls whose surrounding function name contains 'session' or 'sid'. This is achieved via a simpler `ast_call` against `Math.random` with confidence dropped to 0.55, accepting some FP. Reviewers can suppress when not session-related.

```json
{
  "rule_id": "SC-JS-SESSION-001",
  "name": "Predictable session ID via Math.random",
  "language": "javascript",
  "cwe": ["CWE-330"],
  "owasp": ["A07:2021"],
  "severity": "high",
  "confidence": { "base": 0.55 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "Math",
        "callee": "random",
        "message_template": "Math.random is not cryptographically secure — do not use for session/CSRF tokens"
      }
    ]
  },
  "description": "Math.random uses a non-cryptographic PRNG. When used for session identifiers, password reset tokens, or CSRF tokens, an attacker who observes a few outputs can predict subsequent values.",
  "remediation": "Use crypto.randomBytes(16).toString('hex') from Node's crypto module. For browser code, use crypto.getRandomValues.",
  "references": ["https://cwe.mitre.org/data/definitions/330.html"]
}
```

- [ ] **Step 2: Positive fixture**

```javascript
// internal/sast/fixtures/javascript/session_positive.js
function newSessionId() {
  return "sess-" + Math.random().toString(36).slice(2);
}
```

- [ ] **Step 3: Negative fixture**

```javascript
// internal/sast/fixtures/javascript/session_negative.js
const crypto = require("crypto");

function newSessionId() {
  return "sess-" + crypto.randomBytes(16).toString("hex");
}
```

- [ ] **Step 4: Commit + push**

```
git add internal/sast/rules/builtins/SC-JS-SESSION-001.json internal/sast/fixtures/javascript/session_positive.js internal/sast/fixtures/javascript/session_negative.js
git commit -m "feat(sast): SC-JS-SESSION-001 — Math.random as session entropy"
git push
```

### Task C.7: SC-JAVA-SESSION-001 (predictable session ID — java.util.Random)

**Files:**
- Create: `internal/sast/rules/builtins/SC-JAVA-SESSION-001.json`
- Create: `internal/sast/fixtures/java/Session_positive.java`
- Create: `internal/sast/fixtures/java/Session_negative.java`

- [ ] **Step 1: Write the rule**

```json
{
  "rule_id": "SC-JAVA-SESSION-001",
  "name": "Predictable session/token via java.util.Random",
  "language": "java",
  "cwe": ["CWE-330"],
  "owasp": ["A07:2021"],
  "severity": "high",
  "confidence": { "base": 0.55 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "java.util.Random",
        "callee": "nextInt",
        "message_template": "java.util.Random is not cryptographic — use SecureRandom"
      },
      {
        "receiver_fqn": "java.util.Random",
        "callee": "nextLong",
        "message_template": "java.util.Random is not cryptographic"
      },
      {
        "receiver_fqn": "java.util.Random",
        "callee": "nextBytes",
        "message_template": "java.util.Random is not cryptographic"
      }
    ]
  },
  "description": "java.util.Random uses a linear-congruential PRNG that is trivially predictable. Using it for session IDs, tokens, or any security-relevant value is a CWE-330 violation.",
  "remediation": "Use java.security.SecureRandom for any value that must not be predictable.",
  "references": ["https://cwe.mitre.org/data/definitions/330.html"]
}
```

- [ ] **Step 2: Positive fixture**

```java
// internal/sast/fixtures/java/Session_positive.java
import java.util.Random;

public class SessionPositive {
    private static final Random RNG = new Random();

    public String newSessionId() {
        byte[] buf = new byte[16];
        RNG.nextBytes(buf);
        return java.util.Base64.getEncoder().encodeToString(buf);
    }
}
```

- [ ] **Step 3: Negative fixture**

```java
// internal/sast/fixtures/java/Session_negative.java
import java.security.SecureRandom;

public class SessionNegative {
    private static final SecureRandom RNG = new SecureRandom();

    public String newSessionId() {
        byte[] buf = new byte[16];
        RNG.nextBytes(buf);
        return java.util.Base64.getEncoder().encodeToString(buf);
    }
}
```

- [ ] **Step 4: Commit + push**

```
git add internal/sast/rules/builtins/SC-JAVA-SESSION-001.json internal/sast/fixtures/java/Session_positive.java internal/sast/fixtures/java/Session_negative.java
git commit -m "feat(sast): SC-JAVA-SESSION-001 — java.util.Random as security entropy"
git push
```

### Task C.8: SC-CSHARP-SESSION-001 (System.Random)

**Files:**
- Create: `internal/sast/rules/builtins/SC-CSHARP-SESSION-001.json`
- Create: `internal/sast/fixtures/csharp/Session_positive.cs`
- Create: `internal/sast/fixtures/csharp/Session_negative.cs`

- [ ] **Step 1: Rule**

```json
{
  "rule_id": "SC-CSHARP-SESSION-001",
  "name": "Predictable session/token via System.Random",
  "language": "csharp",
  "cwe": ["CWE-330"],
  "owasp": ["A07:2021"],
  "severity": "high",
  "confidence": { "base": 0.55 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "System.Random",
        "callee": "Next",
        "message_template": "System.Random is not cryptographic — use RandomNumberGenerator"
      },
      {
        "receiver_fqn": "System.Random",
        "callee": "NextBytes",
        "message_template": "System.Random.NextBytes is not cryptographic"
      },
      {
        "receiver_fqn": "Random",
        "callee": "Next",
        "message_template": "Random.Next is not cryptographic"
      }
    ]
  },
  "description": "System.Random uses a non-cryptographic PRNG.",
  "remediation": "Use System.Security.Cryptography.RandomNumberGenerator.GetBytes (or .Create()) for any value that must not be predictable.",
  "references": ["https://cwe.mitre.org/data/definitions/330.html"]
}
```

- [ ] **Step 2: Positive fixture**

```csharp
// internal/sast/fixtures/csharp/Session_positive.cs
using System;

public class SessionPositive
{
    private static readonly Random Rng = new Random();

    public string NewSessionId()
    {
        var buf = new byte[16];
        Rng.NextBytes(buf);
        return Convert.ToBase64String(buf);
    }
}
```

- [ ] **Step 3: Negative fixture**

```csharp
// internal/sast/fixtures/csharp/Session_negative.cs
using System;
using System.Security.Cryptography;

public class SessionNegative
{
    public string NewSessionId()
    {
        var buf = RandomNumberGenerator.GetBytes(16);
        return Convert.ToBase64String(buf);
    }
}
```

- [ ] **Step 4: Commit + push**

```
git add internal/sast/rules/builtins/SC-CSHARP-SESSION-001.json internal/sast/fixtures/csharp/Session_positive.cs internal/sast/fixtures/csharp/Session_negative.cs
git commit -m "feat(sast): SC-CSHARP-SESSION-001 — System.Random as security entropy"
git push
```

### Task C.9: SC-PY-SESSION-002 (missing session.regenerate after login)

**Files:**
- Create: `internal/sast/rules/builtins/SC-PY-SESSION-002.json`
- Create: `internal/sast/fixtures/python/session_rotate_positive.py`
- Create: `internal/sast/fixtures/python/session_rotate_negative.py`

This rule is heuristic — confidence is intentionally low (0.55).

- [ ] **Step 1: Rule**

```json
{
  "rule_id": "SC-PY-SESSION-002",
  "name": "Possible session-fixation: login without session reset",
  "language": "python",
  "cwe": ["CWE-384"],
  "owasp": ["A07:2021"],
  "severity": "medium",
  "confidence": { "base": 0.55 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "flask_login",
        "callee": "login_user",
        "arg_index": 0,
        "arg_text_missing_any": ["session.clear", "session.regenerate"],
        "message_template": "flask_login.login_user without nearby session.clear/regenerate may leave the pre-auth session id intact"
      }
    ]
  },
  "description": "Calling flask_login.login_user without first clearing or regenerating the session id leaves the same session identifier alive across the login boundary, which is the canonical session-fixation pattern.",
  "remediation": "Call session.clear() (or a custom regenerate helper) immediately before login_user. flask-login's session-protection helps but does not eliminate the risk on its own.",
  "references": ["https://cwe.mitre.org/data/definitions/384.html"]
}
```

- [ ] **Step 2: Positive fixture**

```python
# internal/sast/fixtures/python/session_rotate_positive.py
from flask import Flask, request
from flask_login import login_user

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    user = authenticate(request.form["username"], request.form["password"])
    login_user(user)  # SC-PY-SESSION-002
    return "ok"

def authenticate(u, p):
    return None
```

- [ ] **Step 3: Negative fixture**

```python
# internal/sast/fixtures/python/session_rotate_negative.py
from flask import Flask, request, session
from flask_login import login_user

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    user = authenticate(request.form["username"], request.form["password"])
    session.clear()
    login_user(user)
    return "ok"

def authenticate(u, p):
    return None
```

- [ ] **Step 4: Commit + push**

```
git add internal/sast/rules/builtins/SC-PY-SESSION-002.json internal/sast/fixtures/python/session_rotate_positive.py internal/sast/fixtures/python/session_rotate_negative.py
git commit -m "feat(sast): SC-PY-SESSION-002 — Flask login_user without session reset"
git push
```

### Task C.10: SC-JAVA-SESSION-002 (missing changeSessionId after login)

**Files:**
- Create: `internal/sast/rules/builtins/SC-JAVA-SESSION-002.json`
- Create: `internal/sast/fixtures/java/Session_rotate_positive.java`
- Create: `internal/sast/fixtures/java/Session_rotate_negative.java`

- [ ] **Step 1: Rule**

```json
{
  "rule_id": "SC-JAVA-SESSION-002",
  "name": "Possible session-fixation: login without changeSessionId",
  "language": "java",
  "cwe": ["CWE-384"],
  "owasp": ["A07:2021"],
  "severity": "medium",
  "confidence": { "base": 0.55 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "receiver_fqn": "javax.servlet.http.HttpServletRequest",
        "callee": "login",
        "arg_index": 0,
        "arg_text_missing_any": ["changeSessionId", "invalidate"],
        "message_template": "request.login without changeSessionId — possible session fixation"
      }
    ]
  },
  "description": "Calling HttpServletRequest.login without subsequently calling changeSessionId() (or invalidating the existing session) leaves the pre-auth session identifier valid post-login.",
  "remediation": "Call request.changeSessionId() after a successful login, or invalidate the session and create a new one.",
  "references": ["https://cwe.mitre.org/data/definitions/384.html"]
}
```

- [ ] **Step 2: Positive fixture**

```java
// internal/sast/fixtures/java/Session_rotate_positive.java
import javax.servlet.http.*;

public class SessionRotatePositive extends HttpServlet {
    public void doPost(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
        try {
            req.login(req.getParameter("u"), req.getParameter("p"));  // SC-JAVA-SESSION-002
        } catch (javax.servlet.ServletException e) {
            resp.sendError(401);
        }
    }
}
```

- [ ] **Step 3: Negative fixture**

```java
// internal/sast/fixtures/java/Session_rotate_negative.java
import javax.servlet.http.*;

public class SessionRotateNegative extends HttpServlet {
    public void doPost(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
        try {
            req.login(req.getParameter("u"), req.getParameter("p"));
            req.changeSessionId();
        } catch (javax.servlet.ServletException e) {
            resp.sendError(401);
        }
    }
}
```

- [ ] **Step 4: Commit + push**

```
git add internal/sast/rules/builtins/SC-JAVA-SESSION-002.json internal/sast/fixtures/java/Session_rotate_positive.java internal/sast/fixtures/java/Session_rotate_negative.java
git commit -m "feat(sast): SC-JAVA-SESSION-002 — servlet login without changeSessionId"
git push
```

### Task C.11: Extend HTTP framework models with auth_header_injection sinks

**Files:**
- Modify: `internal/sast/engine/models/python-stdlib.json`
- Modify: `internal/sast/engine/models/js-http.json`
- Modify: `internal/sast/engine/models/java-servlet.json`
- Modify: `internal/sast/engine/models/csharp-aspnet.json`

For each file, append a new sink alongside the existing `http_header_injection` sinks. The new entries register the same sink positions but with `vuln_class: "auth_header_injection"` — this lets a more specific rule fire on Authorization-header writes.

- [ ] **Step 1: Append to python-stdlib.json**

Read the file, then append before the closing `]`:
```json
,
{"kind": "sink", "receiver_fqn": "flask.Response", "method": "headers.set", "vuln_class": "auth_header_injection"},
{"kind": "sink", "receiver_fqn": "django.http.HttpResponse", "method": "__setitem__", "vuln_class": "auth_header_injection"},
{"kind": "sink", "receiver_fqn": "Response", "method": "headers.set", "vuln_class": "auth_header_injection"}
```

Validate:
```
python3 -c "import json; json.load(open('internal/sast/engine/models/python-stdlib.json'))" && echo OK
```

- [ ] **Step 2: Append to js-http.json**

```json
,
{"kind": "sink", "receiver_fqn": "res", "method": "setHeader", "vuln_class": "auth_header_injection", "args": [1]},
{"kind": "sink", "receiver_fqn": "res", "method": "header", "vuln_class": "auth_header_injection", "args": [1]},
{"kind": "sink", "receiver_fqn": "response", "method": "setHeader", "vuln_class": "auth_header_injection", "args": [1]}
```

Validate.

- [ ] **Step 3: Append to java-servlet.json**

```json
,
{"kind": "sink", "receiver_fqn": "javax.servlet.http.HttpServletResponse", "method": "addHeader", "vuln_class": "auth_header_injection", "args": [1]},
{"kind": "sink", "receiver_fqn": "javax.servlet.http.HttpServletResponse", "method": "setHeader", "vuln_class": "auth_header_injection", "args": [1]},
{"kind": "sink", "receiver_fqn": "jakarta.servlet.http.HttpServletResponse", "method": "addHeader", "vuln_class": "auth_header_injection", "args": [1]},
{"kind": "sink", "receiver_fqn": "jakarta.servlet.http.HttpServletResponse", "method": "setHeader", "vuln_class": "auth_header_injection", "args": [1]}
```

Validate.

- [ ] **Step 4: Append to csharp-aspnet.json**

```json
,
{"kind": "sink", "receiver_fqn": "HttpResponse", "method": "Headers.Add", "vuln_class": "auth_header_injection"},
{"kind": "sink", "receiver_fqn": "HttpResponse", "method": "AppendHeader", "vuln_class": "auth_header_injection"}
```

Validate.

- [ ] **Step 5: Commit + push**

```
git add internal/sast/engine/models/python-stdlib.json internal/sast/engine/models/js-http.json internal/sast/engine/models/java-servlet.json internal/sast/engine/models/csharp-aspnet.json
git commit -m "feat(sast): add auth_header_injection sink class to 4 framework models"
git push
```

Note: The taint engine fires on the first matching sink per call site by `vuln_class`, so existing `http_header_injection` rules and new `auth_header_injection` rules can both match the same call when both classes match. We accept that a single setHeader call can produce findings under both classes if both rules are enabled — fingerprinting deduplicates downstream.

### Task C.12: SC-{LANG}-AUTHHEADER-001 (4 rules)

**Files:**
- Create: `internal/sast/rules/builtins/SC-PY-AUTHHEADER-001.json`
- Create: `internal/sast/rules/builtins/SC-JS-AUTHHEADER-001.json`
- Create: `internal/sast/rules/builtins/SC-JAVA-AUTHHEADER-001.json`
- Create: `internal/sast/rules/builtins/SC-CSHARP-AUTHHEADER-001.json`
- Create: `internal/sast/fixtures/{python,javascript,java,csharp}/authheader_{positive,negative}.{ext}`

All 4 rules are taint-based with `vuln_class: "auth_header_injection"`. They share the same shape; only language differs.

- [ ] **Step 1: SC-PY-AUTHHEADER-001**

```json
{
  "rule_id": "SC-PY-AUTHHEADER-001",
  "name": "Authorization header value flows from user input",
  "language": "python",
  "cwe": ["CWE-113"],
  "owasp": ["A03:2021"],
  "severity": "high",
  "confidence": { "base": 0.70 },
  "detection": { "kind": "taint", "vuln_class": "auth_header_injection" },
  "description": "User input flows into a response Authorization or Cookie header. Beyond response splitting, this can leak credentials sourced from request data into the response.",
  "remediation": "Never reflect request input directly into Authorization or Cookie response headers. If you must, validate against a strict allowlist.",
  "references": ["https://cwe.mitre.org/data/definitions/113.html"]
}
```

- [ ] **Step 2: SC-JS-AUTHHEADER-001**

```json
{
  "rule_id": "SC-JS-AUTHHEADER-001",
  "name": "Authorization header value flows from user input",
  "language": "javascript",
  "cwe": ["CWE-113"],
  "owasp": ["A03:2021"],
  "severity": "high",
  "confidence": { "base": 0.70 },
  "detection": { "kind": "taint", "vuln_class": "auth_header_injection" },
  "description": "User input flows into res.setHeader('Authorization', ...) or similar.",
  "remediation": "Do not echo request input into Authorization/Cookie response headers.",
  "references": ["https://cwe.mitre.org/data/definitions/113.html"]
}
```

- [ ] **Step 3: SC-JAVA-AUTHHEADER-001**

```json
{
  "rule_id": "SC-JAVA-AUTHHEADER-001",
  "name": "Authorization header value flows from user input",
  "language": "java",
  "cwe": ["CWE-113"],
  "owasp": ["A03:2021"],
  "severity": "high",
  "confidence": { "base": 0.70 },
  "detection": { "kind": "taint", "vuln_class": "auth_header_injection" },
  "description": "User input flows into HttpServletResponse.setHeader('Authorization', ...).",
  "remediation": "Do not echo request input into Authorization response headers.",
  "references": ["https://cwe.mitre.org/data/definitions/113.html"]
}
```

- [ ] **Step 4: SC-CSHARP-AUTHHEADER-001**

```json
{
  "rule_id": "SC-CSHARP-AUTHHEADER-001",
  "name": "Authorization header value flows from user input",
  "language": "csharp",
  "cwe": ["CWE-113"],
  "owasp": ["A03:2021"],
  "severity": "high",
  "confidence": { "base": 0.70 },
  "detection": { "kind": "taint", "vuln_class": "auth_header_injection" },
  "description": "User input flows into HttpResponse.Headers.Add('Authorization', ...).",
  "remediation": "Do not echo request input into Authorization response headers.",
  "references": ["https://cwe.mitre.org/data/definitions/113.html"]
}
```

- [ ] **Step 5: Positive fixtures**

`internal/sast/fixtures/python/authheader_positive.py`:

```python
from flask import Flask, request, Response

app = Flask(__name__)

@app.route("/echo")
def echo():
    resp = Response("ok")
    resp.headers.set("Authorization", request.args.get("token", ""))
    return resp
```

`internal/sast/fixtures/javascript/authheader_positive.js`:

```javascript
const express = require("express");
const app = express();

app.get("/echo", (req, res) => {
  res.setHeader("Authorization", req.query.token || "");
  res.send("ok");
});
```

`internal/sast/fixtures/java/Authheader_positive.java`:

```java
import javax.servlet.http.*;
import java.io.IOException;

public class AuthheaderPositive extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setHeader("Authorization", req.getParameter("token"));
        resp.getWriter().write("ok");
    }
}
```

`internal/sast/fixtures/csharp/Authheader_positive.cs`:

```csharp
using Microsoft.AspNetCore.Mvc;

public class AuthheaderController : Controller
{
    public IActionResult Echo(string token)
    {
        Response.Headers.Add("Authorization", token);
        return Ok();
    }
}
```

- [ ] **Step 6: Negative fixtures**

`internal/sast/fixtures/python/authheader_negative.py`:

```python
from flask import Flask, Response
import os

app = Flask(__name__)

@app.route("/static-auth")
def static_auth():
    resp = Response("ok")
    resp.headers.set("Authorization", "Bearer " + os.environ["SERVICE_TOKEN"])
    return resp
```

(JS/Java/C# negative fixtures: similar — response header value sourced from environment / config, not request.)

`internal/sast/fixtures/javascript/authheader_negative.js`:

```javascript
const express = require("express");
const app = express();
const SERVICE_TOKEN = process.env.SERVICE_TOKEN;

app.get("/static-auth", (req, res) => {
  res.setHeader("Authorization", "Bearer " + SERVICE_TOKEN);
  res.send("ok");
});
```

`internal/sast/fixtures/java/Authheader_negative.java`:

```java
import javax.servlet.http.*;
import java.io.IOException;

public class AuthheaderNegative extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setHeader("Authorization", "Bearer " + System.getenv("SERVICE_TOKEN"));
        resp.getWriter().write("ok");
    }
}
```

`internal/sast/fixtures/csharp/Authheader_negative.cs`:

```csharp
using System;
using Microsoft.AspNetCore.Mvc;

public class AuthheaderNegativeController : Controller
{
    public IActionResult Echo()
    {
        Response.Headers.Add("Authorization", "Bearer " + Environment.GetEnvironmentVariable("SERVICE_TOKEN"));
        return Ok();
    }
}
```

- [ ] **Step 7: Commit + push**

```
git add internal/sast/rules/builtins/SC-PY-AUTHHEADER-001.json internal/sast/rules/builtins/SC-JS-AUTHHEADER-001.json internal/sast/rules/builtins/SC-JAVA-AUTHHEADER-001.json internal/sast/rules/builtins/SC-CSHARP-AUTHHEADER-001.json
git add internal/sast/fixtures/python/authheader_positive.py internal/sast/fixtures/python/authheader_negative.py
git add internal/sast/fixtures/javascript/authheader_positive.js internal/sast/fixtures/javascript/authheader_negative.js
git add internal/sast/fixtures/java/Authheader_positive.java internal/sast/fixtures/java/Authheader_negative.java
git add internal/sast/fixtures/csharp/Authheader_positive.cs internal/sast/fixtures/csharp/Authheader_negative.cs
git commit -m "feat(sast): SC-{PY,JS,JAVA,CSHARP}-AUTHHEADER-001 — auth header injection (taint)"
git push
```

### Task C.13: Update loader test for PR C rules

**Files:**
- Modify: `internal/sast/rules/loader_test.go`

- [ ] **Step 1: Append the test**

```go
func TestLoadBuiltins_AuthRulesPRC(t *testing.T) {
	rs, err := LoadBuiltins()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	idIndex := make(map[string]*Rule, len(rs))
	for _, r := range rs {
		idIndex[r.RuleID] = r
	}
	expected := []string{
		"SC-PY-JWT-001", "SC-PY-JWT-002", "SC-PY-JWT-003",
		"SC-JS-JWT-001", "SC-JS-JWT-002", "SC-JS-JWT-003",
		"SC-JAVA-JWT-001", "SC-JAVA-JWT-002", "SC-JAVA-JWT-003",
		"SC-CSHARP-JWT-001", "SC-CSHARP-JWT-002", "SC-CSHARP-JWT-003",
		"SC-JS-SESSION-001",
		"SC-JAVA-SESSION-001",
		"SC-CSHARP-SESSION-001",
		"SC-PY-SESSION-002",
		"SC-JAVA-SESSION-002",
		"SC-PY-AUTHHEADER-001",
		"SC-JS-AUTHHEADER-001",
		"SC-JAVA-AUTHHEADER-001",
		"SC-CSHARP-AUTHHEADER-001",
	}
	for _, id := range expected {
		t.Run(id, func(t *testing.T) {
			r, ok := idIndex[id]
			if !ok {
				t.Fatalf("rule %s missing", id)
			}
			if r.Severity == "" {
				t.Errorf("severity empty")
			}
			if r.Description == "" {
				t.Errorf("description empty")
			}
			if r.Remediation == "" {
				t.Errorf("remediation empty")
			}
		})
	}
}
```

- [ ] **Step 2: Run test**

```
go test ./internal/sast/rules/... -run TestLoadBuiltins_AuthRulesPRC -v 2>&1 | tail -30
```

Expected: PASS, 21 sub-tests.

- [ ] **Step 3: Commit + push**

```
git add internal/sast/rules/loader_test.go
git commit -m "test(sast): cover JWT/session/auth-header rules from PR C"
git push
```

### Task C.14: PR C build, deploy, smoke

- [ ] **Step 1: Run all SAST tests**

```
go test ./internal/sast/...
```

- [ ] **Step 2: Sync, build, deploy** (mirror B.12 with `auth-prc` tag)

```
rsync -az --delete --exclude .git --exclude '*.test' \
  internal/ migrations/ pkg/ rules/ scripts/ Dockerfile go.mod go.sum cmd/ \
  okyay@77.42.34.174:/tmp/sentinelcore-src/
ssh okyay@77.42.34.174 "cd /tmp/sentinelcore-src && \
  docker build -t sentinelcore/controlplane:auth-prc . 2>&1 | tail -5 && \
  docker build -f cmd/sast-worker/Dockerfile -t sentinelcore/sast-worker:auth-prc . 2>&1 | tail -5 && \
  docker tag sentinelcore/controlplane:auth-prc sentinelcore/controlplane:pilot && \
  docker tag sentinelcore/sast-worker:auth-prc sentinelcore/sast-worker:pilot && \
  cd /opt/sentinelcore/compose && docker compose up -d controlplane sast_worker"
curl -s -o /dev/null -w 'healthz: %{http_code}\nreadyz: %{http_code}\n' \
  https://sentinelcore.resiliencetech.com.tr/healthz
curl -s -o /dev/null -w 'readyz: %{http_code}\n' \
  https://sentinelcore.resiliencetech.com.tr/readyz
```

PR C is complete. 76 → 97 total rules.

---

## PR D — CSRF unsafe-compare (3 rules) + final smoke

### Task D.1: SC-JS-CSRF-001

**Files:**
- Create: `internal/sast/rules/builtins/SC-JS-CSRF-001.json`
- Create: `internal/sast/fixtures/javascript/csrf_positive.js`
- Create: `internal/sast/fixtures/javascript/csrf_negative.js`

Strategy: detect CSRF token comparison without `crypto.timingSafeEqual`. We match calls inside functions whose name contains "csrf" or "verifyToken" — this isn't directly expressible, so we use a `arg_text_contains_any` heuristic on the function-scope source text.

The simplest concrete pattern: detect `req.body.csrfToken === ` / `req.body.csrfToken == ` style comparisons. Since binary expressions are not Call instructions, we approximate via tree-sitter source text pattern: emit a synthetic ast_call against the function-level source containing both `csrfToken` and `===` but not `timingSafeEqual`.

Implementation simplification: rule fires on any function call named "verifyCsrf"/"checkCsrfToken"/"compareTokens" whose body source-text contains `===` or `==` and lacks `timingSafeEqual`. This is fragile; alternative is a dedicated detection kind. We accept the heuristic at confidence 0.55.

- [ ] **Step 1: Rule**

```json
{
  "rule_id": "SC-JS-CSRF-001",
  "name": "CSRF token compared with non-constant-time operator",
  "language": "javascript",
  "cwe": ["CWE-208", "CWE-352"],
  "owasp": ["A01:2021"],
  "severity": "medium",
  "confidence": { "base": 0.55 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "callee": "verifyCsrf",
        "arg_index": 0,
        "arg_text_contains_any": ["===", "=="],
        "arg_text_missing_any": ["timingSafeEqual"],
        "message_template": "verifyCsrf-style helper compares tokens with === / == — use crypto.timingSafeEqual"
      },
      {
        "callee": "checkCsrfToken",
        "arg_index": 0,
        "arg_text_contains_any": ["===", "=="],
        "arg_text_missing_any": ["timingSafeEqual"],
        "message_template": "checkCsrfToken compares tokens with === / =="
      }
    ]
  },
  "description": "CSRF/auth token comparison via === / == leaks the prefix length through timing — easier to recognize as a heuristic when wrapped in a verifyCsrf-named helper. Real fix: use crypto.timingSafeEqual.",
  "remediation": "Replace `a === b` with `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))`.",
  "references": ["https://cwe.mitre.org/data/definitions/208.html"]
}
```

- [ ] **Step 2: Positive fixture**

```javascript
// internal/sast/fixtures/javascript/csrf_positive.js
function verifyCsrf(req) {
  return req.body.csrfToken === req.session.csrfToken;
}
```

- [ ] **Step 3: Negative fixture**

```javascript
// internal/sast/fixtures/javascript/csrf_negative.js
const crypto = require("crypto");

function verifyCsrf(req) {
  const a = Buffer.from(req.body.csrfToken || "", "utf-8");
  const b = Buffer.from(req.session.csrfToken || "", "utf-8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
```

- [ ] **Step 4: Commit + push**

```
git add internal/sast/rules/builtins/SC-JS-CSRF-001.json internal/sast/fixtures/javascript/csrf_positive.js internal/sast/fixtures/javascript/csrf_negative.js
git commit -m "feat(sast): SC-JS-CSRF-001 — CSRF token compared without timingSafeEqual"
git push
```

### Task D.2: SC-PY-CSRF-001

**Files:**
- Create: `internal/sast/rules/builtins/SC-PY-CSRF-001.json`
- Create: `internal/sast/fixtures/python/csrf_positive.py`
- Create: `internal/sast/fixtures/python/csrf_negative.py`

- [ ] **Step 1: Rule**

```json
{
  "rule_id": "SC-PY-CSRF-001",
  "name": "CSRF token compared with non-constant-time operator",
  "language": "python",
  "cwe": ["CWE-208", "CWE-352"],
  "owasp": ["A01:2021"],
  "severity": "medium",
  "confidence": { "base": 0.55 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "callee": "verify_csrf",
        "arg_index": 0,
        "arg_text_contains_any": ["==", "!="],
        "arg_text_missing_any": ["compare_digest"],
        "message_template": "verify_csrf compares tokens with == — use hmac.compare_digest"
      },
      {
        "callee": "check_csrf_token",
        "arg_index": 0,
        "arg_text_contains_any": ["==", "!="],
        "arg_text_missing_any": ["compare_digest"],
        "message_template": "check_csrf_token compares tokens with =="
      }
    ]
  },
  "description": "CSRF token comparison via == leaks prefix length through timing.",
  "remediation": "Use hmac.compare_digest(a, b) for constant-time comparison.",
  "references": ["https://cwe.mitre.org/data/definitions/208.html"]
}
```

- [ ] **Step 2: Positive fixture**

```python
# internal/sast/fixtures/python/csrf_positive.py
def verify_csrf(req, sess):
    return req["csrf_token"] == sess["csrf_token"]
```

- [ ] **Step 3: Negative fixture**

```python
# internal/sast/fixtures/python/csrf_negative.py
import hmac

def verify_csrf(req, sess):
    return hmac.compare_digest(req["csrf_token"], sess["csrf_token"])
```

- [ ] **Step 4: Commit + push**

```
git add internal/sast/rules/builtins/SC-PY-CSRF-001.json internal/sast/fixtures/python/csrf_positive.py internal/sast/fixtures/python/csrf_negative.py
git commit -m "feat(sast): SC-PY-CSRF-001 — CSRF token compared without compare_digest"
git push
```

### Task D.3: SC-JAVA-CSRF-001

**Files:**
- Create: `internal/sast/rules/builtins/SC-JAVA-CSRF-001.json`
- Create: `internal/sast/fixtures/java/Csrf_positive.java`
- Create: `internal/sast/fixtures/java/Csrf_negative.java`

- [ ] **Step 1: Rule**

```json
{
  "rule_id": "SC-JAVA-CSRF-001",
  "name": "CSRF token compared with non-constant-time operator",
  "language": "java",
  "cwe": ["CWE-208", "CWE-352"],
  "owasp": ["A01:2021"],
  "severity": "medium",
  "confidence": { "base": 0.55 },
  "detection": {
    "kind": "ast_call",
    "patterns": [
      {
        "callee": "verifyCsrf",
        "arg_index": 0,
        "arg_text_contains_any": [".equals(", "=="],
        "arg_text_missing_any": ["MessageDigest.isEqual"],
        "message_template": "verifyCsrf uses .equals — switch to MessageDigest.isEqual"
      }
    ]
  },
  "description": "CSRF token comparison via .equals leaks prefix length.",
  "remediation": "Use MessageDigest.isEqual(a, b).",
  "references": ["https://cwe.mitre.org/data/definitions/208.html"]
}
```

- [ ] **Step 2: Positive fixture**

```java
// internal/sast/fixtures/java/Csrf_positive.java
public class CsrfPositive {
    public boolean verifyCsrf(String submitted, String stored) {
        return submitted.equals(stored);
    }
}
```

- [ ] **Step 3: Negative fixture**

```java
// internal/sast/fixtures/java/Csrf_negative.java
import java.security.MessageDigest;

public class CsrfNegative {
    public boolean verifyCsrf(String submitted, String stored) {
        return MessageDigest.isEqual(submitted.getBytes(), stored.getBytes());
    }
}
```

- [ ] **Step 4: Commit + push**

```
git add internal/sast/rules/builtins/SC-JAVA-CSRF-001.json internal/sast/fixtures/java/Csrf_positive.java internal/sast/fixtures/java/Csrf_negative.java
git commit -m "feat(sast): SC-JAVA-CSRF-001 — CSRF token .equals without MessageDigest.isEqual"
git push
```

### Task D.4: Update loader test for CSRF + final aggregate count

**Files:**
- Modify: `internal/sast/rules/loader_test.go`

- [ ] **Step 1: Append**

```go
func TestLoadBuiltins_CSRFRulesPR(t *testing.T) {
	rs, err := LoadBuiltins()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	idIndex := make(map[string]*Rule, len(rs))
	for _, r := range rs {
		idIndex[r.RuleID] = r
	}
	expected := []string{"SC-JS-CSRF-001", "SC-PY-CSRF-001", "SC-JAVA-CSRF-001"}
	for _, id := range expected {
		t.Run(id, func(t *testing.T) {
			if _, ok := idIndex[id]; !ok {
				t.Fatalf("rule %s missing", id)
			}
		})
	}
}

func TestLoadBuiltins_TotalRuleCount(t *testing.T) {
	rs, err := LoadBuiltins()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rs) < 100 {
		t.Errorf("expected at least 100 rules after Faz 8, got %d", len(rs))
	}
}
```

- [ ] **Step 2: Run**

```
go test ./internal/sast/rules/... -run "TestLoadBuiltins_CSRFRulesPR|TestLoadBuiltins_TotalRuleCount" -v
```

Expected: both PASS.

- [ ] **Step 3: Commit + push**

```
git add internal/sast/rules/loader_test.go
git commit -m "test(sast): cover CSRF rules + assert total rule count >= 100"
git push
```

### Task D.5: Final build, deploy, smoke, open PR

- [ ] **Step 1: Run all SAST tests**

```
go test ./internal/sast/...
```

Expected: PASS for every package, including all new auth rule tests.

- [ ] **Step 2: Sync, build, deploy**

```
rsync -az --delete --exclude .git --exclude '*.test' \
  internal/ migrations/ pkg/ rules/ scripts/ Dockerfile go.mod go.sum cmd/ \
  okyay@77.42.34.174:/tmp/sentinelcore-src/
ssh okyay@77.42.34.174 "cd /tmp/sentinelcore-src && \
  docker build -t sentinelcore/controlplane:auth-prd . 2>&1 | tail -5 && \
  docker build -f cmd/sast-worker/Dockerfile -t sentinelcore/sast-worker:auth-prd . 2>&1 | tail -5 && \
  docker tag sentinelcore/controlplane:auth-prd sentinelcore/controlplane:pilot && \
  docker tag sentinelcore/sast-worker:auth-prd sentinelcore/sast-worker:pilot && \
  docker tag sentinelcore/controlplane:auth-prd sentinelcore/controlplane:auth-final && \
  docker tag sentinelcore/sast-worker:auth-prd sentinelcore/sast-worker:auth-final && \
  cd /opt/sentinelcore/compose && docker compose up -d controlplane sast_worker"
curl -s -o /dev/null -w 'healthz: %{http_code}\nreadyz: %{http_code}\n' \
  https://sentinelcore.resiliencetech.com.tr/healthz
curl -s -o /dev/null -w 'readyz: %{http_code}\n' \
  https://sentinelcore.resiliencetech.com.tr/readyz
```

- [ ] **Step 3: Smoke test — trigger SAST scan against demo project**

```
TOKEN=$(curl -s -X POST https://sentinelcore.resiliencetech.com.tr/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@sentinel.io","password":"SentinelDemo1!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")
PROJECT_ID=44444444-4444-4444-4444-444444444401
ARTIFACT=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "https://sentinelcore.resiliencetech.com.tr/api/v1/projects/$PROJECT_ID/source-artifacts" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('source_artifacts',[{}])[0].get('id',''))" 2>/dev/null)
if [ -n "$ARTIFACT" ]; then
  curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    "https://sentinelcore.resiliencetech.com.tr/api/v1/projects/$PROJECT_ID/scans" \
    -d "{\"scan_type\":\"sast\",\"source_artifact_id\":\"$ARTIFACT\",\"scan_profile\":\"standard\"}"
fi
sleep 30
curl -s -H "Authorization: Bearer $TOKEN" 'https://sentinelcore.resiliencetech.com.tr/api/v1/findings?limit=500' \
  | python3 -c "
import sys, json
data = json.load(sys.stdin)
findings = data.get('findings', [])
print(f'total findings: {len(findings)}')
ids = sorted({f.get('rule_id') for f in findings if f.get('rule_id')})
auth_ids = [i for i in ids if any(k in i for k in ['COOKIE','JWT','SESSION','AUTHHEADER','CSRF'])]
print('auth-class rule_ids in findings:', auth_ids)
"
```

Expected: scan creates a job and at least one auth-class rule_id appears in findings, OR the seeded artifact does not exercise auth flows (acceptable — manual dogfood scan can verify after).

- [ ] **Step 4: Open the GitHub PR**

```
git push
gh pr create --base phase1/core-platform --title "feat(sast): Faz 8 — auth/authz/session/jwt/cookie/csrf (36 new rules)" --body "$(cat <<'EOF'
## Summary
- Adds 36 new SAST rules across Python, JavaScript, Java, and C# covering cookie attributes (Secure / HttpOnly / SameSite × 4 langs), JWT (verify=False / alg=none / hardcoded secret × 4 langs), session (predictable IDs × 3 langs, missing rotation × 2 langs), authorization-header injection (taint × 4 langs), and CSRF unsafe compare (× 3 langs).
- Adds minimal engine extension: `arg_text_contains_any` / `arg_text_missing_any` matchers operate on per-operand source-text spans now propagated by all four AST frontends.
- Total SAST rule count: 64 → 100.

## Test plan
- [x] `go test ./internal/sast/...` passes locally.
- [x] All four `TestLoadBuiltins_*PR` test functions pass (Cookie, AuthRulesPRC, CSRFRulesPR, TotalRuleCount ≥ 100).
- [x] controlplane:auth-prd + sast-worker:auth-prd images build cleanly.
- [x] /healthz + /readyz return 200 after deploy.
- [ ] SAST scan against the seeded demo project surfaces at least one new auth-class rule_id.
EOF
)"
```

---

## Self-review

### Spec coverage

| Spec section | Implementing task(s) |
|--------------|----------------------|
| §3 New vuln_class values | A.3 (schema), C.1 (jwt), C.11 (auth_header_injection), B.1-B.4 (cookie_misconfig sinks), C.6-C.10 (weak_session_id, session_no_rotate), D.1-D.3 (csrf_weak_compare) |
| §4 Engine extension | A.1, A.2, A.3, A.4, A.5, A.6 (schema + IR + matcher + tests); A.7-A.10 (frontend wiring) |
| §5.1 Cookie attribute rules | B.1-B.4 (models), B.5-B.10 (rules + fixtures), B.11 (loader test) |
| §5.2 JWT rules | C.1 (models), C.2-C.5 (12 rules + fixtures) |
| §5.3 Session rules | C.6-C.10 (5 rules + fixtures) |
| §5.4 Authorization header injection | C.11 (sink extensions), C.12 (4 rules + fixtures) |
| §5.5 CSRF unsafe compare | D.1-D.3 (3 rules + fixtures) |
| §6 PR strategy | A.* (engine), B.* (cookies), C.* (jwt/session/auth-header), D.* (csrf + final) |
| §7 File layout | All Create/Modify entries match the spec's §7 table |
| §8 False-positive strategy | Confidence values in each rule reflect §8 tier guidance |
| §9 Testing | Loader tests in B.11, C.13, D.4; matcher unit test in A.6; fixture-driven worker_test auto-runs |
| §10 Risks | Risk 1 (engine cross-cuts adapters) addressed by per-frontend tasks A.7-A.10; Risk 2-4 (cookie dialect drift, FPs) addressed via multi-pattern rules and confidence tuning; Risk 5 (4 deploys) is the cost of the 4-PR strategy |

### Placeholder scan

No "TBD", "TODO", or "implement later" in any task. Every step is runnable. Two reasonable judgment calls explicitly documented:

1. Java cookie rule (`Task B.9`) detects setSecure/setHttpOnly absence by scanning the source-text of the cookie variable expression — confidence kept at 0.65 to reflect inherent FP risk when setters are called via helper methods.
2. CSRF unsafe-compare rules (D.1-D.3) match by function name ("verifyCsrf"/"check_csrf_token"/"verifyCsrf") plus surrounding-source heuristic. Confidence 0.55 reflects fragility; documented in spec §8.

### Type consistency

- `vuln_class` literals used: `cookie_misconfig`, `jwt_unverified`, `jwt_weak_alg`, `weak_session_id`, `session_no_rotate`, `auth_header_injection`, `csrf_weak_compare` — each appears in framework-model JSON (PR A) and in matching rule files with identical spelling.
- New IR field `ArgSourceText` defined in A.1, populated in A.2 builder helper, propagated in A.7-A.10 frontends, consumed in A.4 matcher. Names match across all five files.
- Schema field `ArgTextContainsAny` / `ArgTextMissingAny` defined in A.3, consumed in A.4 — names match.
- Rule IDs in loader test functions (B.11, C.13, D.4) match exactly the rule IDs created in their respective PRs — verified by name.
- PR-letter Docker image tags (`auth-pra`, `auth-prb`, `auth-prc`, `auth-prd`) used consistently in build/deploy steps for each PR.

No drift, no contradictions.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-02-auth-authz-session.md`. Two execution options:

**1. Subagent-Driven (recommended)** — Dispatch a fresh subagent per task, review between tasks, fast iteration. Each task is independent at this granularity; the plan structure aligns with subagent-driven flow. PR A engine work is sequential (A.1 → A.2 → A.3 → A.4 → A.5 → A.6 → A.7-A.10 in any order → A.11 → A.12); PRs B/C/D have parallelism within each PR after the framework-model task.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.
