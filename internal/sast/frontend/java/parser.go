package java

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
)

// Parse tokenizes and parses a single Java source file into SentinelIR.
// relPath is the artifact-relative path (e.g. "src/main/java/com/example/Foo.java")
// and is used to derive a stable Module.ID.
//
// The parser is a single linear pass over the token stream with a brace-depth
// state machine:
//
//   - At top level: consume package, imports, annotations, and type
//     declarations (class/interface/enum).
//   - Inside a class body: consume fields, methods, nested types, and
//     annotations. Method declarations are detected by the IDENT LPAREN
//     RPAREN LBRACE pattern.
//   - Inside a method body: emit ir.OpCall instructions for every method
//     invocation the walker encounters, including invocations nested inside
//     other invocations' arguments.
//
// The parser is resilient to ill-formed input: an unterminated string, a
// mismatched brace, or an unknown construct never crashes — the walker
// simply advances and continues. The worst case is a partial module with
// some calls missed, which the engine handles correctly (it just produces
// fewer findings).
func Parse(relPath string, src []byte) *ir.Module {
	tokens := Tokenize(src)
	p := &parser{
		tokens:     tokens,
		src:        src,
		lineStarts: computeLineStarts(src),
		// java.lang.* is auto-imported in every Java file.
		imports: map[string]string{
			"String":         "java.lang.String",
			"Object":         "java.lang.Object",
			"Runtime":        "java.lang.Runtime",
			"ProcessBuilder": "java.lang.ProcessBuilder",
			"Process":        "java.lang.Process",
			"System":         "java.lang.System",
			"Math":           "java.lang.Math",
			"Integer":        "java.lang.Integer",
			"Long":           "java.lang.Long",
			"Boolean":        "java.lang.Boolean",
			"Exception":      "java.lang.Exception",
			"RuntimeException": "java.lang.RuntimeException",
			"Thread":         "java.lang.Thread",
			"Class":          "java.lang.Class",
			"StringBuilder":  "java.lang.StringBuilder",
			"StringBuffer":   "java.lang.StringBuffer",
		},
		clinitMethods: map[string]*methodCtx{},
		fieldTypes:    map[string]string{},
		mod: &ir.Module{
			ID:       moduleID(relPath),
			Path:     relPath,
			Language: "java",
		},
	}
	p.run()
	return p.mod
}

// moduleID is SHA-256(path) rendered as lowercase hex. Deterministic so
// re-parsing the same file always yields the same ID; the engine uses this
// as part of the finding fingerprint.
func moduleID(relPath string) string {
	sum := sha256.Sum256([]byte(relPath))
	return hex.EncodeToString(sum[:])
}

// computeLineStarts returns the byte offset of the first character of each
// 1-indexed line. lineStarts[0] is unused so that lineStarts[N] gives the
// start of line N.
func computeLineStarts(src []byte) []int {
	starts := []int{0, 0} // lineStarts[1] = 0
	for i := 0; i < len(src); i++ {
		if src[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// srcSpan returns the verbatim source text from (startLine,startCol) to
// (endLine,endCol), inclusive of the start and exclusive of the end. Lines
// are 1-indexed; columns are 1-indexed and treated as byte offsets within
// the line (good enough for ASCII-dominant source). Returns "" on any
// out-of-range span.
func (p *parser) srcSpan(startLine, startCol, endLine, endCol int) string {
	if startLine < 1 || endLine < startLine || endLine >= len(p.lineStarts) {
		return ""
	}
	startByte := p.lineStarts[startLine] + startCol - 1
	endByte := p.lineStarts[endLine] + endCol - 1
	if startByte < 0 || endByte > len(p.src) || endByte < startByte {
		return ""
	}
	return string(p.src[startByte:endByte])
}

// callSiteTextByTokens reconstructs the verbatim source text of a call
// expression spanning from the token at startTokIdx through the token at
// endTokIdx (inclusive). Returns "" if any index is out of range.
func (p *parser) callSiteTextByTokens(startTokIdx, endTokIdx int) string {
	if startTokIdx < 0 || startTokIdx >= len(p.tokens) ||
		endTokIdx < 0 || endTokIdx >= len(p.tokens) ||
		endTokIdx < startTokIdx {
		return ""
	}
	start := p.tokens[startTokIdx]
	end := p.tokens[endTokIdx]
	endCol := end.Col + len(end.Val)
	return p.srcSpan(start.Line, start.Col, end.Line, endCol)
}

// parser holds the walker's mutable state. None of it survives outside a
// Parse call, so the package is safe to use from multiple goroutines.
type parser struct {
	tokens     []Token
	pos        int
	src        []byte
	lineStarts []int

	mod *ir.Module

	packageName string
	// imports maps a simple class name (e.g. "Cipher") to its fully-qualified
	// name ("javax.crypto.Cipher"). Populated from "import" declarations. The
	// call-site receiver resolver uses this to turn bare identifiers back
	// into FQNs for rule matching.
	imports map[string]string
	// wildcards holds unresolved "import java.util.*"-style imports. Unused
	// in Chunk SAST-2 — present so the taint engine in Chunk SAST-3 can
	// mark receivers as "possibly java.util.*" without reparsing.
	wildcards []string

	// classStack tracks the currently-open classes. Nested classes push new
	// entries; each entry has a fully-qualified name built from the enclosing
	// package + outer class.
	classStack []*ir.Class
	// methodStack tracks currently-open method contexts. Calls found by the
	// walker are attached to the top of this stack.
	methodStack []*methodCtx
	// braceStack tracks what each open brace represents.
	braceStack []braceKind
	// clinitMethods caches the synthetic <clinit> method context for each class.
	clinitMethods map[string]*methodCtx
	// fieldTypes maps class-level field names to their resolved FQN types,
	// used by the receiver resolver for calls like `log.info(...)`.
	fieldTypes map[string]string
}

// methodCtx bundles the ir.Function being populated with its current basic
// block, a local-variable → SSA-value mapping, and a local-variable → type
// mapping. The type mapping lets the taint engine resolve receiver types
// for calls like `stmt.executeQuery(sql)` where `stmt` is a local var.
type methodCtx struct {
	fn        *ir.Function
	block     *ir.BasicBlock
	locals    map[string]ir.ValueID // varName → most-recent SSA value
	localType map[string]string     // varName → resolved FQN (or simple name if no import)
	nextValue ir.ValueID            // monotonically increasing per-function
}

func (m *methodCtx) newValue() ir.ValueID {
	v := m.nextValue
	m.nextValue++
	return v
}

func (m *methodCtx) emit(inst *ir.Instruction) {
	m.block.Instructions = append(m.block.Instructions, inst)
}

type braceKind int

const (
	// kindClassBody is the body of a class, interface, or enum declaration.
	// Method declarations, field declarations, and nested type declarations
	// live at this depth.
	kindClassBody braceKind = iota
	// kindMethodBody is the outer brace of a method implementation.
	kindMethodBody
	// kindBlock is any other brace: static initializer, if/else, for, while,
	// try/catch/finally, lambda body, array initializer, etc. The parser
	// treats these uniformly — they're all just "inside a method" for the
	// purposes of call-site emission.
	kindBlock
)

// run drives the main walker loop until EOF.
func (p *parser) run() {
	for !p.eof() {
		p.step()
	}
}

// step dispatches one parser action based on current brace context. It is
// the single place where the walker decides "what am I looking at right
// now". Every step advances at least one token or pops a brace, guaranteeing
// forward progress even on malformed input.
func (p *parser) step() {
	// Closing brace pops state regardless of context.
	if p.peekPunct("}") {
		p.popBrace()
		p.advance()
		return
	}
	// Annotations are syntactic noise for our purposes — skip them wherever
	// they appear. This covers @Override, @RequestMapping("/foo"),
	// @SuppressWarnings("unchecked"), @NotNull on parameters, etc.
	if p.peekPunct("@") {
		p.skipAnnotation()
		return
	}

	// Dispatch on brace context.
	if len(p.braceStack) == 0 {
		p.stepTopLevel()
		return
	}
	switch p.braceStack[len(p.braceStack)-1] {
	case kindClassBody:
		p.stepClassBody()
	default:
		p.stepMethodBody()
	}
}

// stepTopLevel handles package, import, modifier-keyword skips, and
// top-level type declarations. Anything it doesn't recognize is skipped
// so the walker continues forward.
func (p *parser) stepTopLevel() {
	if p.peekIdent("package") {
		p.parsePackage()
		return
	}
	if p.peekIdent("import") {
		p.parseImport()
		return
	}
	if p.isModifier() {
		p.advance()
		return
	}
	if p.peekIdent("class") || p.peekIdent("interface") || p.peekIdent("enum") {
		p.beginClass()
		return
	}
	p.advance()
}

// parsePackage consumes a 'package a.b.c ;' declaration and records the
// package name in the parser state. The ir.Module also gets its Package
// field updated.
func (p *parser) parsePackage() {
	p.advance() // 'package'
	var parts []string
	for !p.eof() && !p.peekPunct(";") {
		t := p.peek()
		if t.Kind == TokIdent {
			parts = append(parts, t.Val)
		}
		p.advance()
	}
	if p.peekPunct(";") {
		p.advance()
	}
	p.packageName = strings.Join(parts, ".")
	p.mod.Package = p.packageName
}

// parseImport consumes an 'import [static] a.b.C ;' or 'import a.b.* ;'
// declaration and updates the imports map.
func (p *parser) parseImport() {
	p.advance() // 'import'
	if p.peekIdent("static") {
		p.advance()
	}
	var parts []string
	wildcard := false
	for !p.eof() && !p.peekPunct(";") {
		t := p.peek()
		if t.Kind == TokIdent {
			parts = append(parts, t.Val)
		} else if t.Kind == TokPunct && t.Val == "*" {
			wildcard = true
		}
		p.advance()
	}
	if p.peekPunct(";") {
		p.advance()
	}
	if len(parts) == 0 {
		return
	}
	fqn := strings.Join(parts, ".")
	if wildcard {
		p.wildcards = append(p.wildcards, fqn)
		return
	}
	simple := parts[len(parts)-1]
	p.imports[simple] = fqn
	p.mod.Imports = append(p.mod.Imports, fqn)
}

// beginClass consumes a 'class|interface|enum IDENT ... {' header and pushes
// a new class context. Generic parameters, extends, and implements clauses
// are skipped — we only need the class name and FQN for Chunk SAST-2.
func (p *parser) beginClass() {
	p.advance() // class/interface/enum
	if p.peek().Kind != TokIdent {
		return
	}
	simpleName := p.peek().Val
	line := p.peek().Line
	p.advance()

	var fqn string
	if len(p.classStack) > 0 {
		fqn = p.classStack[len(p.classStack)-1].FQN + "." + simpleName
	} else if p.packageName != "" {
		fqn = p.packageName + "." + simpleName
	} else {
		fqn = simpleName
	}

	// Skip generics, extends, implements — scan forward to the opening brace.
	// Depth counting on < and > is not required because we stop at the first
	// '{' we see, and braces can't appear inside a class header.
	for !p.eof() && !p.peekPunct("{") {
		p.advance()
	}
	if !p.peekPunct("{") {
		return
	}
	p.advance() // consume '{'

	cls := &ir.Class{
		Name: simpleName,
		FQN:  fqn,
	}
	_ = line
	p.mod.Classes = append(p.mod.Classes, cls)
	p.classStack = append(p.classStack, cls)
	p.braceStack = append(p.braceStack, kindClassBody)
}

// stepClassBody handles one class-body construct: modifiers, nested types,
// method declarations, field declarations (skipped), static/instance
// initializers (skipped). Method declaration detection is the interesting
// case — see the inline comments.
func (p *parser) stepClassBody() {
	if p.peekPunct("{") {
		// Static initializer or instance initializer block — we push a
		// kindBlock so the matching '}' pops back to class body. We do NOT
		// emit calls found inside initializers in Chunk SAST-2; they have
		// no enclosing method context, so they'd be silently dropped by
		// emitCall anyway.
		p.braceStack = append(p.braceStack, kindBlock)
		p.advance()
		return
	}
	if p.peekPunct(";") {
		p.advance()
		return
	}
	if p.isModifier() {
		p.advance()
		return
	}
	if p.peekIdent("class") || p.peekIdent("interface") || p.peekIdent("enum") {
		p.beginClass()
		return
	}

	// Field type tracking: record the declared type of class-level fields
	// so the receiver resolver can resolve calls like `log.info(...)` to
	// `org.slf4j.Logger.info(...)`. This runs before tryEmitFieldInit
	// and handles BOTH string-initialized and method-initialized fields.
	p.trackFieldType()

	// Field initializer detection: look for `IDENT IDENT = expr ;` pattern
	// (e.g. `String API_KEY = "sk-live-xxx";`). If found, emit a Store
	// instruction on a synthetic "<clinit>" method so the secret detector
	// can see field-level string assignments.
	if p.tryEmitFieldInit() {
		return
	}

	// Method-or-field detection: look for the first IDENT '(' pair that
	// occurs before any statement-level terminator. If found, check what
	// comes after the matching ')'. If it's '{', this is a method with a
	// body; push methodBody and enter it. If it's ';', this is an abstract
	// or interface method; skip to the ';'. If it's '=' or ',', this is a
	// field initializer — skip to the next ';'.
	identIdx, parenIdx := p.findMethodHeader()
	if identIdx < 0 {
		// No method pattern found in the look-ahead window; skip forward.
		p.advance()
		return
	}

	// Find the matching ')'.
	parenEnd := p.matchParen(parenIdx)
	if parenEnd < 0 {
		p.advance()
		return
	}

	// Skip optional 'throws X, Y, Z' clause.
	after := parenEnd + 1
	if after < len(p.tokens) && p.tokens[after].Kind == TokIdent && p.tokens[after].Val == "throws" {
		for after < len(p.tokens) {
			t := p.tokens[after]
			if t.Kind == TokPunct && (t.Val == "{" || t.Val == ";") {
				break
			}
			after++
		}
	}
	if after >= len(p.tokens) {
		p.advance()
		return
	}
	next := p.tokens[after]
	if next.Kind == TokPunct && next.Val == "{" {
		// Method with body.
		ident := p.tokens[identIdx]
		p.beginMethod(ident.Val, ident.Line, ident.Col, parenIdx, parenEnd, after)
		return
	}
	if next.Kind == TokPunct && next.Val == ";" {
		// Abstract / interface method — no body. Skip to just past the ';'.
		p.pos = after + 1
		return
	}
	// Not a method decl (probably a field with a method-call initializer
	// like `Foo x = bar();`). Skip forward past the next terminator so we
	// don't re-examine this same pattern.
	for p.pos < len(p.tokens) {
		t := p.peek()
		if t.Kind == TokPunct && (t.Val == ";" || t.Val == "}") {
			break
		}
		p.advance()
	}
}

// findMethodHeader scans forward from the current position looking for the
// first `IDENT (` pair that could be a method declaration header. Returns
// (identIdx, parenIdx) or (-1, -1) if no such pair is found before a
// statement-level terminator (`;`, `=`, `{`, `}`).
//
// The identIdx check is slightly stricter than "any IDENT" — it must be a
// non-keyword identifier, so `if (`, `for (`, `while (`, `switch (`,
// `return (`, `new (`, `catch (`, `synchronized (`, `try (`, and `throw (`
// patterns don't get mistaken for method headers.
func (p *parser) findMethodHeader() (int, int) {
	for i := p.pos; i < len(p.tokens); i++ {
		t := p.tokens[i]
		if t.Kind == TokPunct {
			switch t.Val {
			case ";", "=", "{", "}":
				return -1, -1
			}
		}
		if t.Kind == TokIdent && i+1 < len(p.tokens) {
			next := p.tokens[i+1]
			if next.Kind == TokPunct && next.Val == "(" && !isReservedCallKeyword(t.Val) {
				return i, i + 1
			}
		}
	}
	return -1, -1
}

// matchParen returns the index of the ')' that matches the '(' at openIdx,
// or -1 if no match is found before EOF.
func (p *parser) matchParen(openIdx int) int {
	depth := 0
	for i := openIdx; i < len(p.tokens); i++ {
		t := p.tokens[i]
		if t.Kind == TokPunct && t.Val == "(" {
			depth++
		} else if t.Kind == TokPunct && t.Val == ")" {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// beginMethod creates a Function and enters its body.
// parenOpen/parenClose are the indices of the parameter list parens.
// braceIdx is the index of the '{' token that starts the body.
func (p *parser) beginMethod(name string, line, col, parenOpen, parenClose, braceIdx int) {
	if len(p.classStack) == 0 {
		p.pos = braceIdx + 1
		return
	}
	cls := p.classStack[len(p.classStack)-1]
	fn := &ir.Function{
		Name:       name,
		FQN:        cls.FQN + "." + name,
		ReturnType: ir.Unknown(),
		Loc:        ir.Location{Line: line, Column: col},
	}
	cls.Methods = append(cls.Methods, fn)

	block := &ir.BasicBlock{ID: 0}
	fn.Blocks = append(fn.Blocks, block)

	mctx := &methodCtx{
		fn:        fn,
		block:     block,
		locals:    map[string]ir.ValueID{},
		localType: map[string]string{},
		nextValue: 1,
	}
	// Parse method parameters from the token stream between the parentheses
	// to seed localType with the declared parameter types. This lets the
	// receiver resolver match `request.getParameter(...)` when `request` is
	// declared as `HttpServletRequest`.
	p.seedParamTypes(mctx, parenOpen, parenClose)

	p.methodStack = append(p.methodStack, mctx)
	p.braceStack = append(p.braceStack, kindMethodBody)
	p.pos = braceIdx + 1
}

// stepMethodBody handles one token inside a method or a block nested inside
// a method. It detects:
//   - call sites (IDENT '(' ...)
//   - local variable declarations: Type var = expr;
//   - assignments: var = expr;
//   - string concat: expr + expr (emitted as BinOp for taint propagation)
//   - nested blocks: { ... }
func (p *parser) stepMethodBody() {
	if p.peekPunct("{") {
		p.braceStack = append(p.braceStack, kindBlock)
		p.advance()
		return
	}

	// Detect assignment-like patterns: `Type var = expr;` or `var = expr;`.
	// We look for `IDENT IDENT =` (typed declaration) or `IDENT =` (reassignment).
	if p.peek().Kind == TokIdent {
		// Type var = expr; → `String id = request.getParameter("id");`
		if p.peekAt(1).Kind == TokIdent && p.peekAt(2).Kind == TokPunct && p.peekAt(2).Val == "=" {
			p.parseLocalDecl()
			return
		}
		// var = expr; → `id = request.getParameter("id");`
		if p.peekAt(1).Kind == TokPunct && p.peekAt(1).Val == "=" {
			p.parseAssignment()
			return
		}
		// Call: IDENT '(' ...
		if p.peekAt(1).Kind == TokPunct && p.peekAt(1).Val == "(" && !isReservedCallKeyword(p.peek().Val) {
			p.tryEmitCall()
			return
		}
	}
	p.advance()
}

// parseLocalDecl handles `Type varName = expr;` inside a method body. It
// emits a Store instruction mapping varName to the expression's value, and
// records the declared type so the receiver resolver can use it.
func (p *parser) parseLocalDecl() {
	// tokens: [0]=Type [1]=varName [2]='='
	typeName := p.peek().Val
	varName := p.peekAt(1).Val
	varLine := p.peekAt(1).Line
	varCol := p.peekAt(1).Col
	p.advance() // skip type
	p.advance() // skip varName
	p.advance() // skip '='

	// Record the declared type. Try explicit imports first, then wildcards.
	if ctx := p.topMethod(); ctx != nil {
		fqn := typeName
		if resolved, ok := p.imports[typeName]; ok {
			fqn = resolved
		} else {
			// Wildcard resolution: java.io.* + ObjectInputStream → java.io.ObjectInputStream
			for _, wc := range p.wildcards {
				candidate := wc + "." + typeName
				fqn = candidate
				break // use first wildcard match
			}
		}
		ctx.localType[varName] = fqn
	}

	// Parse the RHS expression up to ';'. This is a simplified walk that
	// detects calls, string concats, and variable references, returning
	// the SSA value of the overall expression.
	val := p.parseExpression(varLine, varCol)

	if ctx := p.topMethod(); ctx != nil {
		ctx.locals[varName] = val
		ctx.emit(&ir.Instruction{
			Op:       ir.OpStore,
			Operands: []ir.Operand{{Kind: ir.OperandConstString, StrVal: varName}, ir.ValueRef(val)},
			Loc:      ir.Location{Line: varLine, Column: varCol},
		})
	}
	// Consume the trailing ';' if present.
	if p.peekPunct(";") {
		p.advance()
	}
}

// parseAssignment handles `varName = expr;` inside a method body.
func (p *parser) parseAssignment() {
	varName := p.peek().Val
	varLine := p.peek().Line
	varCol := p.peek().Col
	p.advance() // skip varName
	p.advance() // skip '='

	val := p.parseExpression(varLine, varCol)

	if ctx := p.topMethod(); ctx != nil {
		ctx.locals[varName] = val
		ctx.emit(&ir.Instruction{
			Op:       ir.OpStore,
			Operands: []ir.Operand{{Kind: ir.OperandConstString, StrVal: varName}, ir.ValueRef(val)},
			Loc:      ir.Location{Line: varLine, Column: varCol},
		})
	}
	if p.peekPunct(";") {
		p.advance()
	}
}

// parseExpression parses a simplified right-hand-side expression until a ';'
// or ')' at depth 0. It handles:
//   - method calls → emits Call instruction, returns its result value
//   - string literals → returns a const value
//   - variable references → returns the local's current SSA value
//   - string concatenation with '+' → emits BinOp, returns result value
//   - nested expressions in parens
//
// Returns the SSA ValueID of the overall expression.
func (p *parser) parseExpression(hintLine, hintCol int) ir.ValueID {
	ctx := p.topMethod()
	if ctx == nil {
		p.skipToSemicolon()
		return 0
	}

	var resultValue ir.ValueID
	depth := 0

	for !p.eof() {
		t := p.peek()
		// Stop at statement-level terminators (adjusting for paren depth).
		if t.Kind == TokPunct {
			switch t.Val {
			case ";":
				if depth == 0 {
					return resultValue
				}
			case ")":
				if depth == 0 {
					return resultValue
				}
				depth--
				p.advance()
				continue
			case "(":
				depth++
				p.advance()
				continue
			case "{", "}":
				return resultValue
			case "+":
				// String concatenation. Left side is resultValue, parse right.
				loc := ir.Location{Line: t.Line, Column: t.Col}
				p.advance() // skip '+'
				rightVal := p.parseExpressionAtom()
				if resultValue != 0 || rightVal != 0 {
					newVal := ctx.newValue()
					ctx.emit(&ir.Instruction{
						Op:         ir.OpBinOp,
						Result:     newVal,
						ResultType: ir.Nominal("java.lang.String"),
						Operands:   []ir.Operand{ir.ValueRef(resultValue), ir.ValueRef(rightVal)},
						Loc:        loc,
						Callee:     "+", // overloaded: we store the operator in Callee for BinOp
					})
					resultValue = newVal
				}
				continue
			}
		}

		// Parse an atom (call, literal, variable ref) and set resultValue.
		resultValue = p.parseExpressionAtom()
	}
	return resultValue
}

// parseExpressionAtom handles a single expression term: a method call, a
// string literal, an integer literal, or a variable reference. Returns the
// SSA value. Does NOT handle '+' — that's in parseExpression.
func (p *parser) parseExpressionAtom() ir.ValueID {
	ctx := p.topMethod()
	if ctx == nil {
		p.advance()
		return 0
	}

	t := p.peek()

	// String literal.
	if t.Kind == TokString {
		val := ctx.newValue()
		ctx.emit(&ir.Instruction{
			Op:         ir.OpConst,
			Result:     val,
			ResultType: ir.Nominal("java.lang.String"),
			Operands:   []ir.Operand{ir.ConstString(t.Val)},
			Loc:        ir.Location{Line: t.Line, Column: t.Col},
		})
		p.advance()
		return val
	}

	// Number literal.
	if t.Kind == TokNumber {
		val := ctx.newValue()
		ctx.emit(&ir.Instruction{
			Op:         ir.OpConst,
			Result:     val,
			ResultType: ir.Primitive("int"),
			Operands:   []ir.Operand{{Kind: ir.OperandConstString, StrVal: t.Val}},
			Loc:        ir.Location{Line: t.Line, Column: t.Col},
		})
		p.advance()
		return val
	}

	// Constructor: `new ClassName(args)` → emit Call with callee="<init>"
	// and receiverType = resolved(ClassName). This models File, FileInputStream,
	// ProcessBuilder constructors as call sites for the taint engine.
	if t.Kind == TokIdent && t.Val == "new" {
		newTokIdx := p.pos
		p.advance() // skip 'new'
		if p.peek().Kind == TokIdent {
			className := p.peek().Val
			classLine := p.peek().Line
			classCol := p.peek().Col
			fqn := className
			if resolved, ok := p.imports[className]; ok {
				fqn = resolved
			}
			// Find the '(' after the class name (might have generics <T> between).
			p.advance() // skip ClassName
			for p.peekPunct("<") {
				// Skip generic args.
				depth := 0
				for !p.eof() {
					if p.peekPunct("<") {
						depth++
					} else if p.peekPunct(">") {
						depth--
						if depth == 0 {
							p.advance()
							break
						}
					}
					p.advance()
				}
			}
			if p.peekPunct("(") {
				openParen := p.pos
				args := p.scanCallArgs(openParen + 1)
				closeIdx := p.matchParen(openParen)
				if closeIdx >= 0 {
					p.pos = closeIdx + 1
				} else {
					p.advance()
				}
				callText := p.callSiteTextByTokens(newTokIdx, closeIdx)
				resultVal := ctx.newValue()
				ctx.emit(&ir.Instruction{
					Op:            ir.OpCall,
					Result:        resultVal,
					ResultType:    ir.Nominal(fqn),
					ReceiverType:  fqn,
					Callee:        "<init>",
					CalleeFQN:     fqn + ".<init>",
					Operands:      args,
					Loc:           ir.Location{Line: classLine, Column: classCol},
					ArgSourceText: []string{callText},
				})
				return resultVal
			}
		}
		return 0
	}

	// Identifier: could be a method call (IDENT '('), a dotted call
	// (IDENT.IDENT...IDENT '('), or a variable reference.
	if t.Kind == TokIdent && !isReservedCallKeyword(t.Val) {
		// Walk forward through dots to find a potential call.
		chainStartIdx := p.pos
		callIdx := p.findCallInChain()
		if callIdx >= 0 {
			return p.emitCallFromExpression(chainStartIdx, callIdx)
		}
		// Variable reference.
		if v, ok := ctx.locals[t.Val]; ok {
			p.advance()
			// Consume trailing dots (field access chains we don't model).
			for p.peekPunct(".") && p.peekAt(1).Kind == TokIdent {
				p.advance() // '.'
				p.advance() // field
			}
			return v
		}
	}

	// Anything else: skip one token.
	p.advance()
	return 0
}

// findCallInChain looks from the current position through an ident.ident...
// chain and returns the index of the callee IDENT if it's followed by '('.
// Returns -1 if no call is found.
func (p *parser) findCallInChain() int {
	i := p.pos
	for i < len(p.tokens) {
		t := p.tokens[i]
		if t.Kind != TokIdent {
			return -1
		}
		// Check if this ident is followed by '('.
		if i+1 < len(p.tokens) && p.tokens[i+1].Kind == TokPunct && p.tokens[i+1].Val == "(" {
			if !isReservedCallKeyword(t.Val) {
				return i
			}
			return -1
		}
		// Check for dot continuation.
		if i+1 < len(p.tokens) && p.tokens[i+1].Kind == TokPunct && p.tokens[i+1].Val == "." {
			i += 2
			continue
		}
		return -1
	}
	return -1
}

// emitCallFromExpression emits a Call instruction from inside an expression
// context (like the RHS of an assignment). Advances past the entire
// `receiver.callee(args)` span including the closing `)`. Returns the
// call's result SSA value.
// chainStartIdx is the token index of the first token in the receiver chain
// (used to capture the full call-site text including the receiver).
func (p *parser) emitCallFromExpression(chainStartIdx, calleeIdx int) ir.ValueID {
	ctx := p.topMethod()
	if ctx == nil {
		p.advance()
		return 0
	}
	calleeTok := p.tokens[calleeIdx]
	receiverFQN := p.resolveReceiver(calleeIdx)
	callee := calleeTok.Val
	calleeFQN := ""
	if receiverFQN != "" {
		calleeFQN = receiverFQN + "." + callee
	}

	// Position at the '(' following the callee.
	openParen := calleeIdx + 1
	// Scan args without consuming.
	args := p.scanCallArgs(openParen + 1)

	// Find the matching ')' and advance past it.
	closeIdx := p.matchParen(openParen)
	if closeIdx >= 0 {
		p.pos = closeIdx + 1
	} else {
		p.pos = openParen + 1
	}

	callText := p.callSiteTextByTokens(chainStartIdx, closeIdx)
	resultVal := ctx.newValue()
	inst := &ir.Instruction{
		Op:            ir.OpCall,
		Result:        resultVal,
		ResultType:    ir.Unknown(),
		ReceiverType:  receiverFQN,
		Callee:        callee,
		CalleeFQN:     calleeFQN,
		Operands:      args,
		Loc:           ir.Location{Line: calleeTok.Line, Column: calleeTok.Col},
		ArgSourceText: []string{callText},
	}
	ctx.emit(inst)
	return resultVal
}

// topMethod returns the current method context, or nil if we're not inside a
// method body.
// seedParamTypes scans the tokens between parenOpen ('(') and parenClose
// (')') to extract parameter declarations: `Type paramName` pairs separated
// by commas. For each pair, it records paramName → resolved FQN of Type in
// mctx.localType so the receiver resolver can use it.
func (p *parser) seedParamTypes(mctx *methodCtx, parenOpen, parenClose int) {
	// Walk tokens between ( and ), splitting by ','. Each chunk should be
	// of the form: [annotations...] Type [generics] paramName.
	// We parse from right to left within each chunk: last IDENT before comma
	// or ')' is the param name, the IDENT before it is the type.
	i := parenOpen + 1
	for i < parenClose {
		// Collect tokens until ',' or parenClose.
		start := i
		for i < parenClose {
			t := p.tokens[i]
			if t.Kind == TokPunct && t.Val == "," {
				break
			}
			i++
		}
		end := i // exclusive
		if i < parenClose {
			i++ // skip ','
		}
		// Find last two IDENTs in [start, end).
		var lastIdent, secondLastIdent int = -1, -1
		for j := start; j < end; j++ {
			if p.tokens[j].Kind == TokIdent {
				secondLastIdent = lastIdent
				lastIdent = j
			}
		}
		if lastIdent < 0 || secondLastIdent < 0 {
			continue
		}
		paramName := p.tokens[lastIdent].Val
		typeName := p.tokens[secondLastIdent].Val
		// Resolve the type via imports.
		fqn := typeName
		if resolved, ok := p.imports[typeName]; ok {
			fqn = resolved
		}
		mctx.localType[paramName] = fqn

		// Also register in fn.Parameters and locals so the taint engine's
		// summary computation can seed taint on specific parameters.
		paramVal := mctx.newValue()
		mctx.fn.Parameters = append(mctx.fn.Parameters, ir.Parameter{
			Name:  paramName,
			Type:  ir.Nominal(fqn),
			Value: paramVal,
		})
		mctx.locals[paramName] = paramVal
	}
}

// trackFieldType scans forward looking for a `Type fieldName = expr` or
// `Type fieldName;` pattern at class-body scope. Records the field type in
// the parser's fieldTypes map (not in <clinit>, to avoid creating a method).
func (p *parser) trackFieldType() {
	start := p.pos
	limit := start + 20
	if limit > len(p.tokens) {
		limit = len(p.tokens)
	}
	for i := start; i+1 < limit; i++ {
		t := p.tokens[i]
		if t.Kind == TokPunct && (t.Val == ";" || t.Val == "=" || t.Val == "{" || t.Val == "}") {
			break
		}
		if t.Kind == TokIdent && i+1 < limit && p.tokens[i+1].Kind == TokIdent {
			next := p.tokens[i+1]
			if i+2 < limit {
				after := p.tokens[i+2]
				if after.Kind == TokPunct && (after.Val == "=" || after.Val == ";") {
					typeName := t.Val
					fieldName := next.Val
					fqn := typeName
					if resolved, ok := p.imports[typeName]; ok {
						fqn = resolved
					} else {
						for _, wc := range p.wildcards {
							fqn = wc + "." + typeName
							break
						}
					}
					p.fieldTypes[fieldName] = fqn
					return
				}
			}
		}
	}
}

// tryEmitFieldInit detects class-level field declarations with string-literal
// initializers: `Type fieldName = "value";`. It emits a Store instruction on
// a synthetic `<clinit>` method attached to the current class so the secret
// detector can see the assignment. Returns true if a field init was consumed.
func (p *parser) tryEmitFieldInit() bool {
	// Scan forward from current position looking for `IDENT IDENT = STRING ;`
	// or `IDENT IDENT = STRING + STRING ;` (common multi-line concat pattern).
	// We look at most 30 tokens ahead to avoid scanning the whole file.
	start := p.pos
	limit := start + 30
	if limit > len(p.tokens) {
		limit = len(p.tokens)
	}

	// Find an `= STRING` or `= "..."` pattern.
	eqIdx := -1
	for i := start; i < limit; i++ {
		t := p.tokens[i]
		if t.Kind == TokPunct && t.Val == "=" {
			eqIdx = i
			break
		}
		if t.Kind == TokPunct && (t.Val == ";" || t.Val == "{" || t.Val == "}" || t.Val == "(") {
			return false
		}
	}
	if eqIdx < 0 || eqIdx+1 >= limit {
		return false
	}

	// The token right after '=' must be a string literal for us to care.
	afterEq := p.tokens[eqIdx+1]
	if afterEq.Kind != TokString {
		return false
	}

	// Walk backward from '=' to find the field name (the IDENT immediately
	// before '='). Skip array brackets [] if present.
	nameIdx := eqIdx - 1
	for nameIdx >= start && p.tokens[nameIdx].Kind == TokPunct && (p.tokens[nameIdx].Val == "]" || p.tokens[nameIdx].Val == "[") {
		nameIdx--
	}
	if nameIdx < start || p.tokens[nameIdx].Kind != TokIdent {
		return false
	}
	fieldName := p.tokens[nameIdx].Val
	fieldLine := p.tokens[nameIdx].Line
	fieldCol := p.tokens[nameIdx].Col
	stringVal := afterEq.Val

	// Emit a Store instruction on a synthetic <clinit> method.
	if len(p.classStack) > 0 {
		cls := p.classStack[len(p.classStack)-1]
		clinit := p.getOrCreateClinitMethod(cls)
		clinit.block.Instructions = append(clinit.block.Instructions, &ir.Instruction{
			Op:       ir.OpStore,
			Operands: []ir.Operand{
				ir.ConstString(fieldName),
				ir.ConstString(stringVal),
			},
			Loc: ir.Location{Line: fieldLine, Column: fieldCol},
		})
	}

	// Advance past the entire field declaration up to ';'.
	for p.pos < len(p.tokens) {
		if p.peekPunct(";") {
			p.advance()
			break
		}
		p.advance()
	}
	return true
}

// getOrCreateClinitMethod returns a synthetic "<clinit>" method on the class,
// creating it on the first call and reusing it for subsequent fields.
func (p *parser) getOrCreateClinitMethod(cls *ir.Class) *methodCtx {
	if mc, ok := p.clinitMethods[cls.FQN]; ok {
		return mc
	}

	fn := &ir.Function{
		Name:       "<clinit>",
		FQN:        cls.FQN + ".<clinit>",
		ReturnType: ir.Unknown(),
	}
	block := &ir.BasicBlock{ID: 0}
	fn.Blocks = []*ir.BasicBlock{block}
	cls.Methods = append(cls.Methods, fn)

	mc := &methodCtx{fn: fn, block: block, locals: map[string]ir.ValueID{}, localType: map[string]string{}, nextValue: 1}
	p.clinitMethods[cls.FQN] = mc
	return mc
}

func (p *parser) topMethod() *methodCtx {
	if len(p.methodStack) == 0 {
		return nil
	}
	return p.methodStack[len(p.methodStack)-1]
}

func (p *parser) skipToSemicolon() {
	for !p.eof() && !p.peekPunct(";") {
		p.advance()
	}
	if p.peekPunct(";") {
		p.advance()
	}
}

// tryEmitCall records the current IDENT '(' as a method invocation, resolves
// its receiver chain, scans its argument list for string-literal operands
// (without consuming them — nested calls are picked up by the main walker),
// and appends an ir.OpCall to the current method's entry block.
func (p *parser) tryEmitCall() {
	calleePos := p.pos
	calleeTok := p.peek()

	receiverFQN := p.resolveReceiver(calleePos)
	callee := calleeTok.Val
	calleeFQN := ""
	if receiverFQN != "" {
		calleeFQN = receiverFQN + "." + callee
	}

	// Scan arguments without consuming them.
	args := p.scanCallArgs(calleePos + 2)

	// Determine the start of the receiver chain by walking backward through
	// `. IDENT` pairs, mirroring the logic in resolveReceiver.
	chainStartIdx := calleePos
	back := calleePos - 1
	for back >= 1 {
		if p.tokens[back].Kind == TokPunct && p.tokens[back].Val == "." &&
			p.tokens[back-1].Kind == TokIdent {
			chainStartIdx = back - 1
			back -= 2
		} else {
			break
		}
	}

	// Find the closing ')' for the call (without consuming; the main walker
	// continues through args to pick up nested calls).
	closeIdx := p.matchParen(calleePos + 1)
	callText := p.callSiteTextByTokens(chainStartIdx, closeIdx)

	if len(p.methodStack) > 0 {
		ctx := p.methodStack[len(p.methodStack)-1]
		inst := &ir.Instruction{
			Op:            ir.OpCall,
			ReceiverType:  receiverFQN,
			Callee:        callee,
			CalleeFQN:     calleeFQN,
			Operands:      args,
			Loc:           ir.Location{Line: calleeTok.Line, Column: calleeTok.Col},
			ArgSourceText: []string{callText},
		}
		ctx.block.Instructions = append(ctx.block.Instructions, inst)
	}

	// Advance past the callee IDENT and the '('. The main walker will
	// continue through the argument tokens, naturally finding any nested
	// calls inside them (e.g. for the outer f(g()) we will emit both f and
	// g as separate instructions).
	p.advance() // IDENT
	p.advance() // (
}

// resolveReceiver walks backward from the callee position through a chain
// of `. IDENT` pairs and turns the chain into a receiver FQN. Heuristics:
//
//  1. No preceding chain → receiver = "" (bare call, probably 'this' or
//     a local helper).
//  2. Single-segment chain beginning with uppercase → look up in imports.
//     If found, return the import FQN (this is the common `Cipher.getInstance`
//     shape). If not found, return the bare name — the rule engine will
//     simply not match unfamiliar receivers.
//  3. Single-segment chain beginning with lowercase → receiver = "" (it's
//     a local variable, parameter, field, or method result; we don't track
//     local types in Chunk SAST-2).
//  4. Multi-segment chain → treat as a fully-qualified name directly. This
//     handles `javax.crypto.Cipher.getInstance(...)` written without an
//     import. Mostly correct in Java; occasional false receivers like
//     `obj.field.method()` produce an unresolvable FQN which simply fails
//     to match any rule.
func (p *parser) resolveReceiver(calleePos int) string {
	var segs []string
	back := calleePos - 1
	for back >= 0 {
		t := p.tokens[back]
		if t.Kind == TokPunct && t.Val == "." && back-1 >= 0 {
			prev := p.tokens[back-1]
			if prev.Kind == TokIdent {
				segs = append([]string{prev.Val}, segs...)
				back -= 2
				continue
			}
		}
		break
	}
	switch len(segs) {
	case 0:
		return ""
	case 1:
		seg := segs[0]
		// Uppercase: class name → import lookup.
		if len(seg) > 0 && seg[0] >= 'A' && seg[0] <= 'Z' {
			if fqn, ok := p.imports[seg]; ok {
				return fqn
			}
			return seg
		}
		// Lowercase: local variable → type lookup.
		if ctx := p.topMethod(); ctx != nil {
			if fqn, ok := ctx.localType[seg]; ok {
				return fqn
			}
		}
		// Fallback: check class-level field types.
		if fqn, ok := p.fieldTypes[seg]; ok {
			return fqn
		}
		return ""
	default:
		return strings.Join(segs, ".")
	}
}

// scanCallArgs returns the list of top-level argument operands for a call
// whose '(' is at position start-1 (i.e. start points at the first token
// inside the parens). It does NOT modify p.pos — the main walker continues
// into the argument tokens itself.
func (p *parser) scanCallArgs(start int) []ir.Operand {
	var locals map[string]ir.ValueID
	if ctx := p.topMethod(); ctx != nil {
		locals = ctx.locals
	}
	var args []ir.Operand
	var current []Token
	depth := 1
	i := start
	for i < len(p.tokens) && depth > 0 {
		t := p.tokens[i]
		if t.Kind == TokPunct {
			switch t.Val {
			case "(":
				depth++
				current = append(current, t)
				i++
				continue
			case ")":
				depth--
				if depth == 0 {
					if len(current) > 0 {
						args = append(args, tokensToOperand(current, locals))
					}
					return args
				}
				current = append(current, t)
				i++
				continue
			case ",":
				if depth == 1 {
					args = append(args, tokensToOperand(current, locals))
					current = nil
					i++
					continue
				}
			}
		}
		current = append(current, t)
		i++
	}
	if len(current) > 0 {
		args = append(args, tokensToOperand(current, locals))
	}
	return args
}

// tokensToOperand converts a span of tokens representing a single argument
// expression into an ir.Operand. If a method context is available and the
// token is a single identifier matching a known local variable, it resolves
// to the variable's SSA value — this is critical for the taint engine to
// track `sql` in `stmt.executeQuery(sql)` back to its tainted definition.
func tokensToOperand(toks []Token, locals map[string]ir.ValueID) ir.Operand {
	if len(toks) == 1 {
		t := toks[0]
		switch t.Kind {
		case TokString:
			return ir.Operand{Kind: ir.OperandConstString, StrVal: t.Val}
		case TokIdent:
			switch t.Val {
			case "true":
				return ir.Operand{Kind: ir.OperandConstBool, BoolVal: true}
			case "false":
				return ir.Operand{Kind: ir.OperandConstBool, BoolVal: false}
			case "null":
				return ir.Operand{Kind: ir.OperandConstNull}
			default:
				// Check local variable mapping.
				if locals != nil {
					if v, ok := locals[t.Val]; ok {
						return ir.Operand{Kind: ir.OperandValue, Value: v}
					}
				}
			}
		}
	}
	// Multi-token expression (e.g. "User token: " + secret). Scan for any
	// identifier that resolves to a local variable — this preserves taint
	// through string concatenation arguments so the taint engine can track
	// flows like `log.info("prefix" + taintedVar)`.
	if locals != nil && len(toks) > 1 {
		for _, t := range toks {
			if t.Kind == TokIdent {
				if v, ok := locals[t.Val]; ok && v != 0 {
					return ir.Operand{Kind: ir.OperandValue, Value: v}
				}
			}
		}
	}
	return ir.Operand{Kind: ir.OperandValue, Value: 0}
}

// popBrace pops the top of braceStack, also popping classStack or
// methodStack depending on the kind.
func (p *parser) popBrace() {
	if len(p.braceStack) == 0 {
		return
	}
	kind := p.braceStack[len(p.braceStack)-1]
	p.braceStack = p.braceStack[:len(p.braceStack)-1]
	switch kind {
	case kindClassBody:
		if len(p.classStack) > 0 {
			p.classStack = p.classStack[:len(p.classStack)-1]
		}
	case kindMethodBody:
		if len(p.methodStack) > 0 {
			p.methodStack = p.methodStack[:len(p.methodStack)-1]
		}
	}
}

// skipAnnotation consumes an annotation: '@' IDENT [. IDENT]* [(…)].
// We skip the whole thing including any argument list so the surrounding
// construct (a method decl, a field, a parameter) parses cleanly.
func (p *parser) skipAnnotation() {
	p.advance() // @
	for p.peek().Kind == TokIdent {
		p.advance()
		if p.peekPunct(".") {
			p.advance()
			continue
		}
		break
	}
	if p.peekPunct("(") {
		p.advance()
		depth := 1
		for !p.eof() && depth > 0 {
			t := p.peek()
			if t.Kind == TokPunct {
				switch t.Val {
				case "(":
					depth++
				case ")":
					depth--
				}
			}
			p.advance()
		}
	}
}

// isReservedCallKeyword returns true for Java keywords that can appear
// immediately before a '(' and are NOT method callees: if, for, while,
// switch, synchronized, catch, return, throw, instanceof, new, try, do,
// this, super, and the primitive type keywords used in casts. Excluding
// these prevents false "call" detections like `if (x > 0)`.
func isReservedCallKeyword(name string) bool {
	_, ok := reservedCallKeywords[name]
	return ok
}

var reservedCallKeywords = map[string]struct{}{
	"if":           {},
	"for":          {},
	"while":        {},
	"do":           {},
	"switch":       {},
	"case":         {},
	"default":      {},
	"return":       {},
	"throw":        {},
	"throws":       {},
	"try":          {},
	"catch":        {},
	"finally":      {},
	"synchronized": {},
	"instanceof":   {},
	"new":          {},
	"class":        {},
	"interface":    {},
	"enum":         {},
	"extends":      {},
	"implements":   {},
	"package":      {},
	"import":       {},
	"static":       {},
	"final":        {},
	"public":       {},
	"private":      {},
	"protected":    {},
	"abstract":     {},
	"native":       {},
	"transient":    {},
	"volatile":     {},
	"strictfp":     {},
	"void":         {},
	// Constructor calls via `this(...)` / `super(...)` exist but are not
	// relevant to any Chunk SAST-2 rule.
	"this":    {},
	"super":   {},
	"byte":    {},
	"short":   {},
	"int":     {},
	"long":    {},
	"float":   {},
	"double":  {},
	"char":    {},
	"boolean": {},
	"true":    {},
	"false":   {},
	"null":    {},
}

// isModifier returns true if the current token is a Java access or
// declaration modifier that can be skipped at top level or class-body level.
func (p *parser) isModifier() bool {
	if p.peek().Kind != TokIdent {
		return false
	}
	switch p.peek().Val {
	case "public", "private", "protected",
		"static", "final", "abstract", "native",
		"transient", "volatile", "strictfp",
		"synchronized", "default", "sealed",
		"non-sealed":
		return true
	}
	return false
}

// --- low-level token helpers ---

func (p *parser) eof() bool {
	return p.pos >= len(p.tokens) || p.tokens[p.pos].Kind == TokEOF
}

func (p *parser) peek() Token {
	if p.pos >= len(p.tokens) {
		return Token{Kind: TokEOF}
	}
	return p.tokens[p.pos]
}

func (p *parser) peekAt(offset int) Token {
	i := p.pos + offset
	if i < 0 || i >= len(p.tokens) {
		return Token{Kind: TokEOF}
	}
	return p.tokens[i]
}

func (p *parser) advance() {
	if p.pos < len(p.tokens) {
		p.pos++
	}
}

func (p *parser) peekIdent(name string) bool {
	t := p.peek()
	return t.Kind == TokIdent && t.Val == name
}

func (p *parser) peekPunct(val string) bool {
	t := p.peek()
	return t.Kind == TokPunct && t.Val == val
}
