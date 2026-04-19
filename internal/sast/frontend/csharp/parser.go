package csharp

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
)

// Parse tokenizes and parses a single C# source file into SentinelIR.
// relPath is the artifact-relative path (e.g. "src/Controllers/UserController.cs")
// and is used to derive a stable Module.ID.
//
// The parser is a single linear pass over the token stream with a brace-depth
// state machine, modeled directly on the Java parser. It handles:
//
//   - `using` directives (imports)
//   - block-scoped and file-scoped `namespace` declarations
//   - class/interface/struct/enum declarations with nested types
//   - method declarations with typed parameters
//   - method invocations with receiver chains
//   - `new Type(args)` constructor calls
//   - string literal arguments and string concatenation
//   - string interpolation ($"...{var}...") with taint propagation
//   - field initializers with string literal values (for secret detection)
//
// The parser is resilient to ill-formed input: an unterminated string, a
// mismatched brace, or an unknown construct never crashes — the walker
// advances and continues. The worst case is a partial module with some calls
// missed, which the engine handles correctly.
func Parse(relPath string, src []byte) *ir.Module {
	tokens := Tokenize(src)
	p := &parser{
		tokens: tokens,
		// Pre-seed imports with the .NET security-relevant types so the
		// parser can resolve Process.Start, SqlCommand, HttpClient, etc.
		// even when the `using` directive is out of scope or missing.
		imports: map[string]string{
			"String":           "System.String",
			"Object":           "System.Object",
			"Console":          "System.Console",
			"Environment":      "System.Environment",
			"File":             "System.IO.File",
			"FileStream":       "System.IO.FileStream",
			"StreamReader":     "System.IO.StreamReader",
			"StreamWriter":     "System.IO.StreamWriter",
			"Path":             "System.IO.Path",
			"Directory":        "System.IO.Directory",
			"Process":          "System.Diagnostics.Process",
			"ProcessStartInfo": "System.Diagnostics.ProcessStartInfo",
			"SqlCommand":       "System.Data.SqlClient.SqlCommand",
			"SqlConnection":    "System.Data.SqlClient.SqlConnection",
			"SqlParameter":     "System.Data.SqlClient.SqlParameter",
			"HttpClient":       "System.Net.Http.HttpClient",
			"HttpRequestMessage": "System.Net.Http.HttpRequestMessage",
			"WebRequest":       "System.Net.WebRequest",
			"WebClient":        "System.Net.WebClient",
			"BinaryFormatter":  "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter",
			"SoapFormatter":    "System.Runtime.Serialization.Formatters.Soap.SoapFormatter",
			"JsonConvert":      "Newtonsoft.Json.JsonConvert",
			"JsonSerializer":   "System.Text.Json.JsonSerializer",
		},
		clinitMethods: map[string]*methodCtx{},
		fieldTypes:    map[string]string{},
		mod: &ir.Module{
			ID:       moduleID(relPath),
			Path:     relPath,
			Language: "csharp",
		},
	}
	p.run()
	return p.mod
}

// moduleID is SHA-256(path) rendered as lowercase hex.
func moduleID(relPath string) string {
	sum := sha256.Sum256([]byte(relPath))
	return hex.EncodeToString(sum[:])
}

// parser holds the walker's mutable state.
type parser struct {
	tokens []Token
	pos    int

	mod *ir.Module

	namespaceName string
	// imports maps a simple class name (e.g. "SqlCommand") to its
	// fully-qualified name ("System.Data.SqlClient.SqlCommand"). Pre-seeded
	// with common security-relevant .NET types and extended per-file based
	// on `using` directives.
	imports map[string]string
	// wildcards holds namespace-level `using` directives (e.g. "System.IO")
	// that act as wildcard imports for all types in that namespace.
	wildcards []string

	classStack    []*ir.Class
	methodStack   []*methodCtx
	braceStack    []braceKind
	clinitMethods map[string]*methodCtx
	fieldTypes    map[string]string
}

// methodCtx bundles the ir.Function being populated with its current basic
// block, a local-variable → SSA-value mapping, and a local-variable → type
// mapping.
type methodCtx struct {
	fn        *ir.Function
	block     *ir.BasicBlock
	locals    map[string]ir.ValueID
	localType map[string]string
	nextValue ir.ValueID
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
	kindClassBody braceKind = iota
	kindMethodBody
	kindBlock
	kindNamespaceBody
)

// run drives the main walker loop until EOF.
func (p *parser) run() {
	for !p.eof() {
		p.step()
	}
}

// step dispatches one parser action based on the current brace context.
func (p *parser) step() {
	if p.peekPunct("}") {
		p.popBrace()
		p.advance()
		return
	}
	// Attributes [Foo] / [Foo(...)] are syntactic noise — skip them.
	if p.peekPunct("[") {
		p.skipAttribute()
		return
	}

	if len(p.braceStack) == 0 {
		p.stepTopLevel()
		return
	}
	switch p.braceStack[len(p.braceStack)-1] {
	case kindClassBody:
		p.stepClassBody()
	case kindNamespaceBody:
		p.stepTopLevel()
	default:
		p.stepMethodBody()
	}
}

// stepTopLevel handles using directives, namespace declarations, type
// declarations. Called at file top level and inside namespace bodies.
func (p *parser) stepTopLevel() {
	if p.peekIdent("using") {
		// Distinguish `using System;` (directive) from `using (var foo = ...)` (statement).
		// At top level we only see directives.
		if len(p.braceStack) == 0 || p.braceStack[len(p.braceStack)-1] == kindNamespaceBody {
			p.parseUsing()
			return
		}
	}
	if p.peekIdent("namespace") {
		p.parseNamespace()
		return
	}
	if p.isModifier() {
		p.advance()
		return
	}
	if p.peekIdent("class") || p.peekIdent("interface") || p.peekIdent("struct") || p.peekIdent("enum") || p.peekIdent("record") {
		p.beginClass()
		return
	}
	p.advance()
}

// parseUsing consumes a `using [static] [alias =] System.X.Y;` directive.
func (p *parser) parseUsing() {
	p.advance() // 'using'
	if p.peekIdent("static") {
		p.advance()
	}
	// Alias form: `using Alias = Full.Qualified.Name;`
	if p.peek().Kind == TokIdent && p.peekAt(1).Kind == TokPunct && p.peekAt(1).Val == "=" {
		alias := p.peek().Val
		p.advance() // alias
		p.advance() // '='
		var parts []string
		for !p.eof() && !p.peekPunct(";") {
			if p.peek().Kind == TokIdent {
				parts = append(parts, p.peek().Val)
			}
			p.advance()
		}
		if p.peekPunct(";") {
			p.advance()
		}
		if len(parts) > 0 {
			fqn := strings.Join(parts, ".")
			p.imports[alias] = fqn
			p.mod.Imports = append(p.mod.Imports, fqn)
		}
		return
	}

	// Simple form: `using System.Data.SqlClient;` → wildcard for that namespace.
	var parts []string
	for !p.eof() && !p.peekPunct(";") {
		if p.peek().Kind == TokIdent {
			parts = append(parts, p.peek().Val)
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
	p.wildcards = append(p.wildcards, fqn)
	p.mod.Imports = append(p.mod.Imports, fqn)

	// Populate imports from knownNamespaceTypes so bare type names (e.g.
	// `HttpRequest`) resolve to the specific namespace the user imported
	// (e.g. Microsoft.AspNetCore.Http). This makes resolution deterministic
	// regardless of the order of `using` directives.
	if types, ok := knownNamespaceTypes[fqn]; ok {
		for _, typeName := range types {
			p.imports[typeName] = fqn + "." + typeName
		}
	}
}

// knownNamespaceTypes maps a .NET namespace to the security-relevant types
// declared in it. When a `using Namespace;` directive is parsed, the parser
// imports these types so the receiver resolver can map bare class names back
// to their FQNs without depending on wildcard iteration order.
var knownNamespaceTypes = map[string][]string{
	"System":                                         {"String", "Object", "Console", "Environment", "Convert", "Uri"},
	"System.IO":                                      {"File", "FileStream", "StreamReader", "StreamWriter", "Path", "Directory", "MemoryStream", "Stream"},
	"System.Diagnostics":                             {"Process", "ProcessStartInfo"},
	"System.Data.SqlClient":                          {"SqlCommand", "SqlConnection", "SqlParameter", "SqlDataReader", "SqlParameterCollection"},
	"Microsoft.Data.SqlClient":                       {"SqlCommand", "SqlConnection", "SqlParameter", "SqlDataReader", "SqlParameterCollection"},
	"System.Net":                                     {"WebRequest", "WebClient", "HttpWebRequest", "HttpWebResponse"},
	"System.Net.Http":                                {"HttpClient", "HttpRequestMessage", "HttpResponseMessage", "HttpClientHandler"},
	"Microsoft.AspNetCore.Http":                      {"HttpRequest", "HttpContext", "HttpResponse"},
	"System.Web":                                     {"HttpRequest", "HttpContext", "HttpResponse"},
	"System.Runtime.Serialization.Formatters.Binary": {"BinaryFormatter"},
	"System.Runtime.Serialization.Formatters.Soap":   {"SoapFormatter"},
	"System.Runtime.Serialization":                   {"NetDataContractSerializer", "DataContractSerializer"},
	"Newtonsoft.Json":                                {"JsonConvert", "JsonSerializer"},
	"System.Text.Json":                               {"JsonSerializer"},
}

// parseNamespace consumes a `namespace X.Y.Z { ... }` or file-scoped
// `namespace X.Y.Z;` declaration. Sets the module's package name.
func (p *parser) parseNamespace() {
	p.advance() // 'namespace'
	var parts []string
	for !p.eof() {
		t := p.peek()
		if t.Kind == TokIdent {
			parts = append(parts, t.Val)
			p.advance()
			continue
		}
		if t.Kind == TokPunct && t.Val == "." {
			p.advance()
			continue
		}
		break
	}
	p.namespaceName = strings.Join(parts, ".")
	if p.mod.Package == "" {
		p.mod.Package = p.namespaceName
	}
	if p.peekPunct("{") {
		// Block-scoped namespace.
		p.advance()
		p.braceStack = append(p.braceStack, kindNamespaceBody)
		return
	}
	if p.peekPunct(";") {
		// File-scoped namespace — applies to rest of file, no brace pushed.
		p.advance()
	}
}

// beginClass consumes `class|interface|struct|enum|record IDENT [: Base[, Iface]*] {`.
func (p *parser) beginClass() {
	p.advance() // class / interface / struct / enum / record
	if p.peek().Kind != TokIdent {
		return
	}
	simpleName := p.peek().Val
	line := p.peek().Line
	p.advance()

	var fqn string
	if len(p.classStack) > 0 {
		fqn = p.classStack[len(p.classStack)-1].FQN + "." + simpleName
	} else if p.namespaceName != "" {
		fqn = p.namespaceName + "." + simpleName
	} else {
		fqn = simpleName
	}

	// Skip generic parameters, base/interface list, where clauses — scan to '{'.
	for !p.eof() && !p.peekPunct("{") {
		// If we hit a ';' before '{' it's a forward declaration or
		// partial member — bail out.
		if p.peekPunct(";") {
			p.advance()
			return
		}
		p.advance()
	}
	if !p.peekPunct("{") {
		return
	}
	p.advance() // consume '{'

	cls := &ir.Class{Name: simpleName, FQN: fqn}
	_ = line
	p.mod.Classes = append(p.mod.Classes, cls)
	p.classStack = append(p.classStack, cls)
	p.braceStack = append(p.braceStack, kindClassBody)
}

// stepClassBody handles one class-body construct.
func (p *parser) stepClassBody() {
	if p.peekPunct("{") {
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
	if p.peekIdent("class") || p.peekIdent("interface") || p.peekIdent("struct") || p.peekIdent("enum") || p.peekIdent("record") {
		p.beginClass()
		return
	}

	// Field type tracking.
	p.trackFieldType()

	// Field initializer with string literal → emit store on <clinit>.
	if p.tryEmitFieldInit() {
		return
	}

	// Method header detection.
	identIdx, parenIdx := p.findMethodHeader()
	if identIdx < 0 {
		p.advance()
		return
	}
	parenEnd := p.matchParen(parenIdx)
	if parenEnd < 0 {
		p.advance()
		return
	}

	// Skip optional `where T : Foo` constraints after the parameter list.
	after := parenEnd + 1
	if after < len(p.tokens) && p.tokens[after].Kind == TokIdent && p.tokens[after].Val == "where" {
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
		ident := p.tokens[identIdx]
		p.beginMethod(ident.Val, ident.Line, ident.Col, parenIdx, parenEnd, after)
		return
	}
	if next.Kind == TokPunct && next.Val == ";" {
		// Interface / abstract method or auto-property getter — no body.
		p.pos = after + 1
		return
	}
	if next.Kind == TokPunct && next.Val == "=>" {
		// Expression-bodied member — for MVP we skip it. Scan to next ';'.
		p.pos = after
		for p.pos < len(p.tokens) {
			t := p.peek()
			if t.Kind == TokPunct && t.Val == ";" {
				p.advance()
				return
			}
			p.advance()
		}
		return
	}
	// Skip forward past the next terminator so we don't loop.
	for p.pos < len(p.tokens) {
		t := p.peek()
		if t.Kind == TokPunct && (t.Val == ";" || t.Val == "}") {
			break
		}
		p.advance()
	}
}

// findMethodHeader scans forward looking for `IDENT (` that looks like a
// method/constructor declaration header.
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

// matchParen finds the ')' that matches the '(' at openIdx.
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
	p.seedParamTypes(mctx, parenOpen, parenClose)

	p.methodStack = append(p.methodStack, mctx)
	p.braceStack = append(p.braceStack, kindMethodBody)
	p.pos = braceIdx + 1
}

// stepMethodBody handles one token inside a method body.
func (p *parser) stepMethodBody() {
	if p.peekPunct("{") {
		p.braceStack = append(p.braceStack, kindBlock)
		p.advance()
		return
	}

	// Skip `await` keyword — still parse the underlying call.
	if p.peekIdent("await") {
		p.advance()
		return
	}
	// `using` statement: `using (var foo = ...) { ... }` or `using var foo = ...;`
	if p.peekIdent("using") {
		p.advance()
		// Skip optional '('.
		if p.peekPunct("(") {
			p.advance()
		}
		return
	}

	if p.peek().Kind == TokIdent {
		// Type var = expr; → `string id = Request.Query["id"];`
		// Also matches `var id = expr;` because `var` is a TokIdent.
		if p.peekAt(1).Kind == TokIdent && p.peekAt(2).Kind == TokPunct && p.peekAt(2).Val == "=" {
			p.parseLocalDecl()
			return
		}
		// var = expr;
		if p.peekAt(1).Kind == TokPunct && p.peekAt(1).Val == "=" {
			p.parseAssignment()
			return
		}
		// Call: IDENT '('
		if p.peekAt(1).Kind == TokPunct && p.peekAt(1).Val == "(" && !isReservedCallKeyword(p.peek().Val) {
			p.tryEmitCall()
			return
		}
	}
	p.advance()
}

// parseLocalDecl handles `Type varName = expr;` (including `var varName = expr;`).
func (p *parser) parseLocalDecl() {
	typeName := p.peek().Val
	varName := p.peekAt(1).Val
	varLine := p.peekAt(1).Line
	varCol := p.peekAt(1).Col
	p.advance() // skip type
	p.advance() // skip varName
	p.advance() // skip '='

	// If the RHS begins with `new ClassName(...)` we can infer the local's
	// type from the constructor class name rather than the (often "var")
	// declared type.
	inferredType := ""
	if p.peekIdent("new") && p.peekAt(1).Kind == TokIdent {
		inferredType = p.peekAt(1).Val
	}

	declaredType := typeName
	if inferredType != "" && (typeName == "var" || typeName == "dynamic") {
		declaredType = inferredType
	}

	if ctx := p.topMethod(); ctx != nil {
		fqn := declaredType
		if resolved, ok := p.imports[declaredType]; ok {
			fqn = resolved
		} else {
			for _, wc := range p.wildcards {
				fqn = wc + "." + declaredType
				break
			}
		}
		ctx.localType[varName] = fqn
	}

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

// parseAssignment handles `varName = expr;`.
func (p *parser) parseAssignment() {
	varName := p.peek().Val
	varLine := p.peek().Line
	varCol := p.peek().Col
	p.advance() // varName
	p.advance() // '='

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

// parseExpression walks a simplified RHS expression until ';' or ')' at depth 0.
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
				loc := ir.Location{Line: t.Line, Column: t.Col}
				p.advance() // skip '+'
				rightVal := p.parseExpressionAtom()
				if resultValue != 0 || rightVal != 0 {
					newVal := ctx.newValue()
					ctx.emit(&ir.Instruction{
						Op:         ir.OpBinOp,
						Result:     newVal,
						ResultType: ir.Nominal("System.String"),
						Operands:   []ir.Operand{ir.ValueRef(resultValue), ir.ValueRef(rightVal)},
						Loc:        loc,
						Callee:     "+",
					})
					resultValue = newVal
				}
				continue
			}
		}

		resultValue = p.parseExpressionAtom()
	}
	return resultValue
}

// parseExpressionAtom handles a single expression term.
func (p *parser) parseExpressionAtom() ir.ValueID {
	ctx := p.topMethod()
	if ctx == nil {
		p.advance()
		return 0
	}

	t := p.peek()

	// String literal — and, if interpolated, propagate taint from each
	// referenced local into a BinOp chain so the sink sees the tainted value.
	if t.Kind == TokString {
		val := ctx.newValue()
		ctx.emit(&ir.Instruction{
			Op:         ir.OpConst,
			Result:     val,
			ResultType: ir.Nominal("System.String"),
			Operands:   []ir.Operand{ir.ConstString(t.Val)},
			Loc:        ir.Location{Line: t.Line, Column: t.Col},
		})
		p.advance()

		// Scan the string value for `{name}` interpolation segments referring
		// to local variables. For each, emit an OpBinOp that joins the
		// current string value with the local's SSA value — this preserves
		// taint through `$"SELECT ... WHERE id = {id}"`.
		for _, name := range scanInterpolatedLocals(t.Val) {
			if localVal, ok := ctx.locals[name]; ok && localVal != 0 {
				newVal := ctx.newValue()
				ctx.emit(&ir.Instruction{
					Op:         ir.OpBinOp,
					Result:     newVal,
					ResultType: ir.Nominal("System.String"),
					Operands:   []ir.Operand{ir.ValueRef(val), ir.ValueRef(localVal)},
					Loc:        ir.Location{Line: t.Line, Column: t.Col},
					Callee:     "+",
				})
				val = newVal
			}
		}
		return val
	}

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

	// Constructor: `new ClassName(args)` → emit Call with callee="<init>".
	if t.Kind == TokIdent && t.Val == "new" {
		p.advance() // skip 'new'
		// Collect dotted class name: `new System.Data.SqlClient.SqlCommand(...)`.
		var classParts []string
		classLine := p.peek().Line
		classCol := p.peek().Col
		for p.peek().Kind == TokIdent {
			classParts = append(classParts, p.peek().Val)
			p.advance()
			if p.peekPunct(".") {
				p.advance()
				continue
			}
			break
		}
		if len(classParts) == 0 {
			return 0
		}
		className := classParts[len(classParts)-1]
		var fqn string
		if len(classParts) > 1 {
			fqn = strings.Join(classParts, ".")
		} else if resolved, ok := p.imports[className]; ok {
			fqn = resolved
		} else {
			fqn = className
			for _, wc := range p.wildcards {
				candidate := wc + "." + className
				// Only use the wildcard if the class name is one we track —
				// otherwise leave the bare name which won't match.
				_ = candidate
			}
			if resolved, ok := p.imports[className]; ok {
				fqn = resolved
			}
		}
		// Skip generic parameters <...>.
		for p.peekPunct("<") {
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
			resultVal := ctx.newValue()
			ctx.emit(&ir.Instruction{
				Op:           ir.OpCall,
				Result:       resultVal,
				ResultType:   ir.Nominal(fqn),
				ReceiverType: fqn,
				Callee:       "<init>",
				CalleeFQN:    fqn + ".<init>",
				Operands:     args,
				Loc:          ir.Location{Line: classLine, Column: classCol},
			})
			return resultVal
		}
		return 0
	}

	// Identifier: could be a method call or a variable reference.
	if t.Kind == TokIdent && !isReservedCallKeyword(t.Val) {
		callIdx := p.findCallInChain()
		if callIdx >= 0 {
			return p.emitCallFromExpression(callIdx)
		}
		if v, ok := ctx.locals[t.Val]; ok {
			p.advance()
			for p.peekPunct(".") && p.peekAt(1).Kind == TokIdent {
				p.advance()
				p.advance()
			}
			return v
		}
	}

	p.advance()
	return 0
}

// findCallInChain walks forward through an ident[.ident]* chain and returns
// the index of the callee ident if followed by `(` or (for property-indexer
// access like `request.Query["id"]`) by `[` after at least one dot hop. A
// bare `arr[0]` with no dot prefix is NOT treated as a call — that's a local
// variable indexer.
func (p *parser) findCallInChain() int {
	i := p.pos
	sawDot := false
	for i < len(p.tokens) {
		t := p.tokens[i]
		if t.Kind != TokIdent {
			return -1
		}
		if i+1 < len(p.tokens) {
			next := p.tokens[i+1]
			if next.Kind == TokPunct && next.Val == "(" {
				if !isReservedCallKeyword(t.Val) {
					return i
				}
				return -1
			}
			if next.Kind == TokPunct && next.Val == "[" && sawDot {
				if !isReservedCallKeyword(t.Val) {
					return i
				}
				return -1
			}
			if next.Kind == TokPunct && (next.Val == "." || next.Val == "?.") {
				sawDot = true
				i += 2
				continue
			}
		}
		return -1
	}
	return -1
}

// emitCallFromExpression emits a Call from inside an expression context,
// advancing past the entire span. Handles both method calls `obj.Method(args)`
// and property-indexer access `obj.Prop[key]` — the latter is modeled as a
// call to the property so the taint engine can treat `request.Query["id"]`
// as a source invocation matching the HttpRequest.Query sink model.
func (p *parser) emitCallFromExpression(calleeIdx int) ir.ValueID {
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

	openIdx := calleeIdx + 1
	var args []ir.Operand
	var closeIdx int
	if openIdx < len(p.tokens) && p.tokens[openIdx].Kind == TokPunct && p.tokens[openIdx].Val == "[" {
		args = p.scanIndexerArgs(openIdx + 1)
		closeIdx = p.matchBracket(openIdx)
	} else {
		args = p.scanCallArgs(openIdx + 1)
		closeIdx = p.matchParen(openIdx)
	}

	if closeIdx >= 0 {
		p.pos = closeIdx + 1
	} else {
		p.pos = openIdx + 1
	}

	resultVal := ctx.newValue()
	inst := &ir.Instruction{
		Op:           ir.OpCall,
		Result:       resultVal,
		ResultType:   ir.Unknown(),
		ReceiverType: receiverFQN,
		Callee:       callee,
		CalleeFQN:    calleeFQN,
		Operands:     args,
		Loc:          ir.Location{Line: calleeTok.Line, Column: calleeTok.Col},
	}
	ctx.emit(inst)
	return resultVal
}

// matchBracket returns the index of the `]` that matches the `[` at openIdx,
// or -1 if no match is found before EOF.
func (p *parser) matchBracket(openIdx int) int {
	depth := 0
	for i := openIdx; i < len(p.tokens); i++ {
		t := p.tokens[i]
		if t.Kind == TokPunct && t.Val == "[" {
			depth++
		} else if t.Kind == TokPunct && t.Val == "]" {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// scanIndexerArgs returns the operand list for an indexer expression whose
// `[` is at position start-1 (start points at the first token inside).
// Tracks bracket depth and splits on top-level commas. Does NOT modify p.pos.
func (p *parser) scanIndexerArgs(start int) []ir.Operand {
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
			case "[":
				depth++
				current = append(current, t)
				i++
				continue
			case "]":
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

// seedParamTypes walks tokens between ( and ) extracting `Type paramName` pairs.
func (p *parser) seedParamTypes(mctx *methodCtx, parenOpen, parenClose int) {
	i := parenOpen + 1
	for i < parenClose {
		start := i
		paren := 0
		for i < parenClose {
			t := p.tokens[i]
			if t.Kind == TokPunct {
				switch t.Val {
				case "(", "<", "[":
					paren++
				case ")", ">", "]":
					if paren > 0 {
						paren--
					}
				case ",":
					if paren == 0 {
						goto doneParam
					}
				}
			}
			i++
		}
	doneParam:
		end := i
		if i < parenClose {
			i++ // skip ','
		}
		// Skip parameter modifiers (ref, out, in, params, this).
		for start < end {
			t := p.tokens[start]
			if t.Kind == TokIdent {
				switch t.Val {
				case "ref", "out", "in", "params", "this":
					start++
					continue
				}
			}
			if t.Kind == TokPunct && t.Val == "[" {
				// Skip attribute on parameter.
				depth := 1
				start++
				for start < end && depth > 0 {
					tt := p.tokens[start]
					if tt.Kind == TokPunct && tt.Val == "[" {
						depth++
					} else if tt.Kind == TokPunct && tt.Val == "]" {
						depth--
					}
					start++
				}
				continue
			}
			break
		}
		// Find last two identifiers: type and name.
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
		fqn := typeName
		if resolved, ok := p.imports[typeName]; ok {
			fqn = resolved
		} else {
			for _, wc := range p.wildcards {
				fqn = wc + "." + typeName
				break
			}
		}
		mctx.localType[paramName] = fqn

		paramVal := mctx.newValue()
		mctx.fn.Parameters = append(mctx.fn.Parameters, ir.Parameter{
			Name:  paramName,
			Type:  ir.Nominal(fqn),
			Value: paramVal,
		})
		mctx.locals[paramName] = paramVal
	}
}

// trackFieldType scans forward to record a `Type fieldName` pattern at class
// scope for later receiver resolution.
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
				if after.Kind == TokPunct && (after.Val == "=" || after.Val == ";" || after.Val == "{") {
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
// initializers and emits a Store on a synthetic <clinit> method for secret
// detection.
func (p *parser) tryEmitFieldInit() bool {
	start := p.pos
	limit := start + 30
	if limit > len(p.tokens) {
		limit = len(p.tokens)
	}

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
	afterEq := p.tokens[eqIdx+1]
	if afterEq.Kind != TokString {
		return false
	}
	// The token before '=' is the field name.
	nameIdx := eqIdx - 1
	if nameIdx < start || p.tokens[nameIdx].Kind != TokIdent {
		return false
	}
	fieldName := p.tokens[nameIdx].Val
	fieldLine := p.tokens[nameIdx].Line
	fieldCol := p.tokens[nameIdx].Col
	stringVal := afterEq.Val

	if len(p.classStack) > 0 {
		cls := p.classStack[len(p.classStack)-1]
		clinit := p.getOrCreateClinitMethod(cls)
		clinit.block.Instructions = append(clinit.block.Instructions, &ir.Instruction{
			Op: ir.OpStore,
			Operands: []ir.Operand{
				ir.ConstString(fieldName),
				ir.ConstString(stringVal),
			},
			Loc: ir.Location{Line: fieldLine, Column: fieldCol},
		})
	}
	for p.pos < len(p.tokens) {
		if p.peekPunct(";") {
			p.advance()
			break
		}
		p.advance()
	}
	return true
}

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

// tryEmitCall records the current IDENT '(' as a method invocation.
func (p *parser) tryEmitCall() {
	calleePos := p.pos
	calleeTok := p.peek()

	receiverFQN := p.resolveReceiver(calleePos)
	callee := calleeTok.Val
	calleeFQN := ""
	if receiverFQN != "" {
		calleeFQN = receiverFQN + "." + callee
	}

	args := p.scanCallArgs(calleePos + 2)

	if len(p.methodStack) > 0 {
		ctx := p.methodStack[len(p.methodStack)-1]
		inst := &ir.Instruction{
			Op:           ir.OpCall,
			ReceiverType: receiverFQN,
			Callee:       callee,
			CalleeFQN:    calleeFQN,
			Operands:     args,
			Loc:          ir.Location{Line: calleeTok.Line, Column: calleeTok.Col},
		}
		ctx.block.Instructions = append(ctx.block.Instructions, inst)
	}

	p.advance() // IDENT
	p.advance() // (
}

// resolveReceiver walks backward from calleePos through `.IDENT` segments.
func (p *parser) resolveReceiver(calleePos int) string {
	var segs []string
	back := calleePos - 1
	for back >= 0 {
		t := p.tokens[back]
		if t.Kind == TokPunct && (t.Val == "." || t.Val == "?.") && back-1 >= 0 {
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
		if len(seg) > 0 && seg[0] >= 'A' && seg[0] <= 'Z' {
			if fqn, ok := p.imports[seg]; ok {
				return fqn
			}
			// Try wildcard resolution for static class references.
			for _, wc := range p.wildcards {
				_ = wc // we don't know which wildcard hosts this type, skip
			}
			return seg
		}
		if ctx := p.topMethod(); ctx != nil {
			if fqn, ok := ctx.localType[seg]; ok {
				return fqn
			}
		}
		if fqn, ok := p.fieldTypes[seg]; ok {
			return fqn
		}
		return ""
	default:
		// Multi-segment. If the first segment is a known local var, try to
		// prepend its type so e.g. `cmd.Parameters.AddWithValue` becomes
		// `<SqlCommand type>.Parameters.AddWithValue` — but keeping it as a
		// literal chain "cmd.Parameters" also works because the sanitizer
		// check has a bare-name fallback.
		return strings.Join(segs, ".")
	}
}

// scanCallArgs returns the top-level operand list for a call at start-1 → '('.
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

// tokensToOperand converts an argument token span into an ir.Operand.
// Handles single-token string/ident/bool/null and multi-token expressions
// by scanning for any local variable reference that preserves taint. Also
// handles interpolated strings whose {expr} segments refer to locals.
func tokensToOperand(toks []Token, locals map[string]ir.ValueID) ir.Operand {
	if len(toks) == 1 {
		t := toks[0]
		switch t.Kind {
		case TokString:
			// Interpolated string: if it contains `{localName}`, propagate
			// the local's taint by returning it as the operand.
			if locals != nil {
				for _, name := range scanInterpolatedLocals(t.Val) {
					if v, ok := locals[name]; ok && v != 0 {
						return ir.Operand{Kind: ir.OperandValue, Value: v}
					}
				}
			}
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
				if locals != nil {
					if v, ok := locals[t.Val]; ok {
						return ir.Operand{Kind: ir.OperandValue, Value: v}
					}
				}
			}
		}
	}
	// Multi-token expression — scan for any known local + any interpolated
	// string referencing a local.
	if locals != nil && len(toks) > 1 {
		for _, t := range toks {
			if t.Kind == TokIdent {
				if v, ok := locals[t.Val]; ok && v != 0 {
					return ir.Operand{Kind: ir.OperandValue, Value: v}
				}
			}
			if t.Kind == TokString {
				for _, name := range scanInterpolatedLocals(t.Val) {
					if v, ok := locals[name]; ok && v != 0 {
						return ir.Operand{Kind: ir.OperandValue, Value: v}
					}
				}
			}
		}
	}
	return ir.Operand{Kind: ir.OperandValue, Value: 0}
}

// scanInterpolatedLocals extracts identifier names from `{name}` segments in
// an interpolated string value. `{name.Prop}` returns "name". `{name,10}` and
// `{name:format}` also return "name". Balanced `{{` is an escape for a
// literal `{` and is ignored.
func scanInterpolatedLocals(s string) []string {
	var out []string
	i := 0
	for i < len(s) {
		if s[i] == '{' {
			// `{{` is a literal `{`, not an interpolation.
			if i+1 < len(s) && s[i+1] == '{' {
				i += 2
				continue
			}
			i++
			start := i
			depth := 1
			for i < len(s) && depth > 0 {
				if s[i] == '{' {
					depth++
				} else if s[i] == '}' {
					depth--
					if depth == 0 {
						break
					}
				}
				i++
			}
			if i > start {
				expr := s[start:i]
				// Trim format/alignment specifiers.
				if idx := strings.IndexAny(expr, ",:"); idx >= 0 {
					expr = expr[:idx]
				}
				// Take only the first identifier (before any `.`).
				if idx := strings.Index(expr, "."); idx >= 0 {
					expr = expr[:idx]
				}
				expr = strings.TrimSpace(expr)
				if expr != "" && isIdentifier(expr) {
					out = append(out, expr)
				}
			}
		}
		i++
	}
	return out
}

func isIdentifier(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if i == 0 {
			if !isIdentStart(b) {
				return false
			}
		} else {
			if !isIdentCont(b) {
				return false
			}
		}
	}
	return true
}

// popBrace pops the top of braceStack plus associated class/method stacks.
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

// skipAttribute consumes `[Attribute]` or `[Attribute(args)]` at top or
// class level.
func (p *parser) skipAttribute() {
	p.advance() // '['
	depth := 1
	for !p.eof() && depth > 0 {
		t := p.peek()
		if t.Kind == TokPunct {
			switch t.Val {
			case "[":
				depth++
			case "]":
				depth--
				if depth == 0 {
					p.advance()
					return
				}
			}
		}
		p.advance()
	}
}

// isReservedCallKeyword: C# keywords that look like IDENT '(' but are not
// method calls.
func isReservedCallKeyword(name string) bool {
	_, ok := reservedCallKeywords[name]
	return ok
}

var reservedCallKeywords = map[string]struct{}{
	"if":        {},
	"for":       {},
	"foreach":   {},
	"while":     {},
	"do":        {},
	"switch":    {},
	"case":      {},
	"default":   {},
	"return":    {},
	"throw":     {},
	"try":       {},
	"catch":     {},
	"finally":   {},
	"lock":      {},
	"using":     {},
	"checked":   {},
	"unchecked": {},
	"fixed":     {},
	"new":       {},
	"class":     {},
	"interface": {},
	"struct":    {},
	"enum":      {},
	"record":    {},
	"namespace": {},
	"public":    {},
	"private":   {},
	"protected": {},
	"internal":  {},
	"static":    {},
	"readonly":  {},
	"const":     {},
	"sealed":    {},
	"abstract":  {},
	"virtual":   {},
	"override":  {},
	"async":     {},
	"await":     {},
	"partial":   {},
	"this":      {},
	"base":      {},
	"var":       {},
	"byte":      {},
	"short":     {},
	"int":       {},
	"uint":      {},
	"long":      {},
	"ulong":     {},
	"float":     {},
	"double":    {},
	"decimal":   {},
	"char":      {},
	"bool":      {},
	"string":    {},
	"object":    {},
	"void":      {},
	"true":      {},
	"false":     {},
	"null":      {},
	"typeof":    {},
	"sizeof":    {},
	"nameof":    {},
	"is":        {},
	"as":        {},
	"in":        {},
	"out":       {},
	"ref":       {},
	"params":    {},
}

// isModifier returns true if the current token is a C# declaration modifier
// that can be skipped at top-level or class-body level.
func (p *parser) isModifier() bool {
	if p.peek().Kind != TokIdent {
		return false
	}
	switch p.peek().Val {
	case "public", "private", "protected", "internal",
		"static", "readonly", "const",
		"sealed", "abstract", "virtual", "override",
		"async", "partial", "extern", "unsafe",
		"new", "volatile", "required":
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
