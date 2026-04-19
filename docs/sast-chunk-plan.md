# SentinelCore SAST — Enterprise MVP Slice Chunk Plan

This document tracks the tightly-scoped SAST MVP slice. The long-term
architecture is documented in `docs/sast-architecture.md` (the Fortify-class
design). This plan is the **executable slice of that architecture** — narrow,
real, benchmarkable, Java-only.

## Scope reminder

- **Language:** Java only
- **Frameworks:** Spring MVC, Servlet, JDBC, Java stdlib (process, filesystem, crypto)
- **Classes:** SQL Injection, Command Injection, Path Traversal, Weak Crypto, Hardcoded Secret
- **Non-goals for the slice:** JS/TS, Python, C#, Go, Ruby, path sensitivity, custom DSLs

## Chunk map

| Chunk | Status | Focus |
|---|---|---|
| **SAST-1** | ✅ Complete | SentinelIR foundation + rule engine core + first-light analyzer with weak-crypto rule on hand-built Java fixtures |
| **SAST-2** | ✅ Complete | Pure-Go Java frontend — hand-rolled tokenizer + structural parser, real `.java` source files round-trip through the existing engine |
| **SAST-3** | ✅ Complete | Taint engine v1 (intra-procedural) — source/sink/sanitizer model + flow walker; Servlet → JDBC SQLi rule SC-JAVA-SQL-001 with evidence chains |
| **SAST-4** | ✅ Complete | Inter-procedural taint — function summaries, CHA call graph, cross-function + cross-class SQLi detection with evidence chains |
| **SAST-5** | ✅ Complete | Command injection (CWE-78) + path traversal (CWE-22) — model packs + rules + tests, fixed per-vulnclass summaries |
| **SAST-6** | ✅ Complete | Hardcoded secret detection — field-init parser + ast_assign detection + name+entropy+prefix heuristic, 3 test fixtures |
| **SAST-7** | ✅ Complete | Findings pipeline — migration 019 (taint_paths), adapter layer, API taint_paths in finding detail, deployed |
| **SAST-8** | ✅ Complete | UI Analysis Trace — collapsible evidence chain in finding detail, Source/Flow/Sink badges, deployed |
| **SAST-9** | ⏳ | Benchmark foundation — small OWASP Benchmark Java subset + difftool for scorecard generation |
| **SAST-10** | ✅ Complete | SAST worker binary + compose service — full E2E verified |

## Chunk SAST-1 — what shipped

### Architecture delivered

- **SentinelIR core** (`internal/sast/ir/`): Module → Class → Function → BasicBlock → Instruction with typed SSA values. Opcode set sized for Chunk SAST-1 (`Call`, `Const`, `Load`, `Store`, `Return`) with reserved slots for later opcodes (`Phi`, `Branch`, `New`, `ExtCall`) so frontends can already emit them without engine rework.
- **Rule engine core** (`internal/sast/engine/`): AST-local matcher for the `ast_call` detection kind. Walks module → class → method → block → instruction, applies every compiled rule's patterns, emits `Finding` records with stable fingerprints and single-step evidence chains. Structured so the taint matcher in Chunk SAST-3 slots in alongside without touching callers.
- **Rule loader** (`internal/sast/rules/`): JSON rule schema with CWE mapping, OWASP mapping, severity, confidence model, remediation text, references, message templates. Strict `Validate()` rejects malformed rules at load time. Regexes are pre-compiled at load so scan-time is allocation-free in the hot path.
- **Fingerprints** (`internal/sast/engine/fingerprint.go`): Stable across cosmetic code changes and across scans. Keyed on `(rule_id, module_path, function_fqn, callee_fqn, key_arg)`. Deliberately excludes line number so re-ordered imports don't churn triage state.
- **First rule**: `SC-JAVA-CRYPTO-001` — weak cryptographic algorithm detection. Two patterns (`Cipher.getInstance` with DES/3DES/RC2/RC4/Blowfish/ECB, `MessageDigest.getInstance` with MD2/MD4/MD5/SHA-1). AST-local, no taint needed.
- **Fixture layer** (`internal/sast/fixtures/`): Hand-built Java IR standing in for the real Java frontend until Chunk SAST-2. Each fixture is documented with the Java source it represents, so Chunk SAST-2 can replay the same shapes once the parser is real.

### Test coverage

- 6 IR unit tests (construction, type equality, deterministic IDs, JSON round-trip)
- 8 rule loader unit tests (builtin load, compile, 6 validation rejection cases)
- 2 fingerprint unit tests (stability + distinctness)
- 7 engine end-to-end tests covering:
  - DES cipher → fires (positive)
  - AES/GCM → does not fire (negative)
  - MD5 hash → fires
  - AES/ECB → fires (mode-level violation even with strong cipher)
  - Mixed batch (3 calls, 1 finding) — proves module-level filtering
  - Non-literal argument → does not fire (documents Chunk SAST-1 limitation)
  - Fingerprint stability across repeat analyses

**Total**: 23 tests, all passing. Full regression across 30 packages: zero failures.

## Chunk SAST-2 — what shipped

### Architecture delivered

- **`internal/sast/frontend/java/lexer.go`** — pure-Go Java tokenizer. Handles line + block comments (including Javadoc), single-line strings with escape decoding, Java 15+ text blocks (`"""…"""`), char literals, numeric literals (int, hex, binary, float with suffixes), identifiers, multi-char operators (`==`, `>>>`, `->`, `::`, etc.), and 1-indexed line/column tracking. Resilient to malformed input — unterminated strings and unterminated block comments produce partial token streams rather than panics, so a single bad file cannot crash the worker.
- **`internal/sast/frontend/java/parser.go`** — structural walker over the token stream with a brace-depth state machine. Recognizes packages, static + wildcard imports, classes/interfaces/enums (including nested), method declarations (detected by the `IDENT(...)…{` pattern with proper field-vs-method disambiguation), and method invocations with receiver chain resolution. Emits SentinelIR directly — no intermediate AST. Receiver chains are resolved by looking up the first capitalized segment in the imports table, so `Cipher.getInstance(...)` becomes a Call with `receiver_type="javax.crypto.Cipher"` automatically.
- **`internal/sast/frontend/java/frontend.go`** — public API: `Parse(relPath, src)`, `ParseFile(absPath, relPath)`, `ParseSource(relPath, src)`, and `WalkJavaFiles(root)` (directory walker with skip list for `target/`, `build/`, `.git/`, `.idea/`, `node_modules/`).
- **6 real `.java` testdata files** (`testdata/*.java`) — mirror the SAST-1 hand-built fixtures but are actual compilable Java source. They serve as the real end-to-end regression set for every future change to the parser or the rule engine.

### Why hand-rolled, not a JVM sidecar

The long-term architecture calls for a JVM sidecar running JavaParser or Eclipse JDT Core. For Chunk SAST-2 I deliberately did not build that. Reasons:

1. **Deployment cost.** A JVM sidecar adds a Gradle project, JNI or UDS plumbing, process lifecycle management, health checks, and a JVM container image. That is a week of work by itself, separate from the parser logic.
2. **CGO constraint.** SentinelCore's Dockerfile disables CGO. tree-sitter is out. Any pure-Go Java parser ecosystem is immature.
3. **IR boundary.** The rule engine talks SentinelIR. Whether IR comes from a hand-rolled walker, a tree-sitter grammar, or a JVM sidecar is invisible to everything above it. The hand-rolled parser can be replaced chunk-by-chunk as semantic needs grow — when Chunk SAST-3 needs local-variable type tracking or Chunk SAST-4 needs cross-file class hierarchy analysis, those will be the triggers to introduce a sidecar.
4. **Scope fit.** The parser correctly handles every pattern in the MVP slice: Spring annotations, Servlet imports, JDBC calls, Java stdlib crypto. It does not handle generics precisely, does not track local variable types, and does not do overload resolution — none of those are needed yet.

### Test coverage

- **6 lexer tests** — basic shape (identifiers, keywords, strings, punctuation), string escape decoding, text blocks, 11 multi-char operator cases, line tracking across block comments, resilience to unterminated strings.
- **7 parser unit tests** — class + method + call extraction, control-flow keyword exclusion (`if/for/while/switch/synchronized/catch/return/throw` are never misrecognized as calls), import resolution, nested classes with dotted FQN, annotation skipping (critical: `@RequestMapping("/foo")` on a method must not look like a call), multiple top-level classes per file, field-vs-method disambiguation.
- **5 end-to-end tests on real `.java` files** — the chunk's main deliverable. WeakCryptoDES.java, StrongCryptoAES.java, WeakHashMD5.java, ECBModeViolation.java, and NonLiteralCipherArg.java are parsed and fed through the existing `engine.NewFromBuiltins()` pipeline. Each assertion checks rule_id, line number, title template expansion, severity, confidence, evidence chain, and fingerprint length.
- **3 additional integration tests** — MixedCryptoBatch real-file (3 crypto calls, 1 finding at the correct line), fingerprint stability across re-parses, fingerprint divergence across different module paths.
- **1 filesystem walker test** — `WalkJavaFiles` picks up all 6 testdata files.

**Total new tests for SAST-2: 22.** All pass. Full regression across 31 packages: clean.

### Explicit limitations (by design for SAST-2)

1. **No generics semantic model.** The tokenizer sees `<` and `>` as individual punctuation. The parser skips past them in class headers and ignores them in method signatures. This is fine for rule matching but will be insufficient when the taint engine needs to understand generic type parameters.
2. **No local-variable type tracking.** When a method body contains `Cipher c = Cipher.getInstance("DES"); c.doFinal(...)`, the walker correctly matches the `Cipher.getInstance` call but emits the subsequent `c.doFinal` with `receiver_type=""` because it doesn't know `c`'s declared type. Chunk SAST-3 will need a simple local-type tracker for taint propagation.
3. **No overload resolution.** `System.out.println(x)` and `System.out.println(y, z)` are both emitted as calls to `println` — we don't distinguish the overloads by parameter count or type. No current rule cares.
4. **Constructor calls use the Call opcode, not a dedicated `new` opcode.** When the walker sees `new Foo(args)`, it emits a regular Call. This is a simplification we can revisit when a rule specifically needs to distinguish constructors (e.g., for unsafe deserialization via `new ObjectInputStream(...)`).

These limitations are explicit, documented, and each has a clear future chunk that will address it when the need arises.

### Why this ordering (continued)

Chunk SAST-2 closes the loop from "engine works on hand-built IR" to "engine works on real source". The IR boundary (Chunk SAST-1's single largest contribution) is now validated — the same engine, the same rules, the same tests, fed by a completely different source (hand-built vs real parser), produce equivalent findings. Every subsequent chunk can now assume: if it emits valid SentinelIR, the engine will analyze it correctly. The frontend is a replaceable component, not a dependency the engine needs to know about.

### Explicit limitations (by design for SAST-1)

1. **No real Java parser yet.** The hand-built fixture layer is the Chunk SAST-1 stand-in. Chunk SAST-2 replaces it with a JVM sidecar using JavaParser. This is why there is no `.java → IR` path yet — we are proving the engine before spending effort on the parser.
2. **No taint analysis.** Only AST-local rules work. SQLi/command-injection/path-traversal require taint and land in Chunks SAST-3+.
3. **No findings pipeline integration.** `Finding` structs are produced but not persisted to `findings.findings` yet. Chunk SAST-7 adds the migration and the adapter.
4. **No UI.** Chunk SAST-8 adds the Analysis Trace block.
5. **No benchmarks.** Chunk SAST-9 adds the OWASP Benchmark subset + difftool.

### Why this ordering

Chunk SAST-1 delivers the three hardest-to-change things first:
- **The IR shape** — every subsequent chunk depends on it, and changing it is expensive.
- **The rule schema** — every rule authored from SAST-2 onward uses it.
- **The fingerprint scheme** — once findings are in the DB, changing fingerprints invalidates triage history.

Getting these right before wiring them into the database, the UI, and the
real parser is the cheapest path to a defensible MVP. The fixture layer is
the deliberate shortcut that lets us exercise all three without the parser
work — and it stays alive past Chunk SAST-2 as the regression test layer
(the IR shapes the real parser must produce for given Java inputs).
