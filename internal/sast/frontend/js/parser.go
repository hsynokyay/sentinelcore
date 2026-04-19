package js

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
)

// Parse tokenizes and parses a JS/TS file into SentinelIR.
func Parse(relPath string, src []byte) *ir.Module {
	tokens := Tokenize(src)
	p := &parser{
		tokens:  tokens,
		imports: map[string]string{},
		mod: &ir.Module{
			ID:       moduleID(relPath),
			Path:     relPath,
			Language: "javascript",
		},
	}
	p.run()
	return p.mod
}

func moduleID(relPath string) string {
	sum := sha256.Sum256([]byte(relPath))
	return hex.EncodeToString(sum[:])
}

type parser struct {
	tokens    []Token
	pos       int
	mod       *ir.Module
	imports   map[string]string // simple name → module path
	funcStack []*funcCtx
}

type funcCtx struct {
	fn        *ir.Function
	block     *ir.BasicBlock
	locals    map[string]ir.ValueID
	localType map[string]string
	nextValue ir.ValueID
}

func (ctx *funcCtx) newValue() ir.ValueID {
	v := ctx.nextValue
	ctx.nextValue++
	return v
}

func (ctx *funcCtx) emit(inst *ir.Instruction) {
	ctx.block.Instructions = append(ctx.block.Instructions, inst)
}

func (p *parser) run() {
	// Create a module-level class to hold functions.
	cls := &ir.Class{Name: "<module>", FQN: p.mod.Path}
	p.mod.Classes = append(p.mod.Classes, cls)

	for !p.eof() {
		p.stepTopLevel(cls)
	}
}

func (p *parser) stepTopLevel(cls *ir.Class) {
	t := p.peek()

	// import statements.
	if t.Kind == TokIdent && t.Val == "import" {
		p.parseImport()
		return
	}

	// require() calls.
	if t.Kind == TokIdent && t.Val == "require" {
		p.advance()
		return
	}

	// const/let/var declarations.
	if t.Kind == TokIdent && (t.Val == "const" || t.Val == "let" || t.Val == "var") {
		p.parseVarDecl(cls)
		return
	}

	// function declarations.
	if t.Kind == TokIdent && (t.Val == "function" || t.Val == "async") {
		p.parseFuncDecl(cls)
		return
	}

	// export.
	if t.Kind == TokIdent && t.Val == "export" {
		p.advance()
		if p.peekIdent("default") {
			p.advance()
		}
		return
	}

	// class declarations.
	if t.Kind == TokIdent && t.Val == "class" {
		p.parseClassDecl(cls)
		return
	}

	// Skip anything else (types, interfaces, etc.)
	p.advance()
}

func (p *parser) parseImport() {
	p.advance() // 'import'
	// Scan to end of import statement.
	var fromModule string
	for !p.eof() && !p.peekPunct(";") && !(p.peek().Kind == TokIdent && p.peek().Val == "import") {
		if p.peekIdent("from") {
			p.advance()
			if p.peek().Kind == TokString {
				fromModule = p.peek().Val
			}
		}
		if p.peek().Kind == TokString && fromModule == "" {
			fromModule = p.peek().Val
		}
		p.advance()
	}
	if p.peekPunct(";") {
		p.advance()
	}
	if fromModule != "" {
		p.mod.Imports = append(p.mod.Imports, fromModule)
	}
}

func (p *parser) parseVarDecl(cls *ir.Class) {
	p.advance() // const/let/var

	// Destructuring: const { exec, spawn } = require("child_process")
	// Check BEFORE the TokIdent gate since `{` is TokPunct.
	if p.peekPunct("{") {
		var names []string
		p.advance() // '{'
		for !p.eof() && !p.peekPunct("}") {
			if p.peek().Kind == TokIdent {
				names = append(names, p.peek().Val)
			}
			p.advance()
		}
		if p.peekPunct("}") {
			p.advance()
		}
		if p.peekPunct("=") {
			p.advance()
			if p.peekIdent("require") {
				p.advance()
				if p.peekPunct("(") {
					p.advance()
					if p.peek().Kind == TokString {
						mod := p.peek().Val
						for _, n := range names {
							p.imports[n] = mod
						}
					}
				}
			}
		}
		p.skipToSemicolon()
		return
	}
	if p.peekPunct("[") {
		p.skipToSemicolon()
		return
	}

	if p.peek().Kind != TokIdent {
		return
	}
	varName := p.peek().Val
	varLine := p.peek().Line
	varCol := p.peek().Col
	p.advance() // name

	// Type annotation — skip.
	if p.peekPunct(":") {
		for !p.eof() && !p.peekPunct("=") && !p.peekPunct(";") {
			p.advance()
		}
	}

	if !p.peekPunct("=") {
		p.skipToSemicolon()
		return
	}
	p.advance() // '='

	// Check for string literal assignment (secrets detection).
	if p.peek().Kind == TokString {
		strVal := p.peek().Val
		strLine := p.peek().Line
		strCol := p.peek().Col
		clinit := p.getClinitFunc(cls)
		clinit.emit(&ir.Instruction{
			Op:       ir.OpStore,
			Operands: []ir.Operand{ir.ConstString(varName), ir.ConstString(strVal)},
			Loc:      ir.Location{Line: strLine, Column: strCol},
		})
		p.advance()
		p.skipToSemicolon()
		return
	}

	// Check for function expression: (params) => { ... } or function(...) { ... }
	if p.peekIdent("function") || p.peekIdent("async") || p.isArrowFunc() {
		fn := p.parseFuncBody(cls, varName, varLine, varCol)
		if fn != nil {
			cls.Methods = append(cls.Methods, fn)
		}
		return
	}

	// require() call.
	if p.peekIdent("require") {
		p.advance()
		if p.peekPunct("(") {
			p.advance()
			if p.peek().Kind == TokString {
				p.imports[varName] = p.peek().Val
			}
		}
		p.skipToSemicolon()
		return
	}

	p.skipToSemicolon()
}

func (p *parser) isArrowFunc() bool {
	// Look ahead for `(...)  => {` pattern.
	if !p.peekPunct("(") {
		return false
	}
	depth := 0
	for i := p.pos; i < len(p.tokens) && i < p.pos+50; i++ {
		if p.tokens[i].Kind == TokPunct && p.tokens[i].Val == "(" {
			depth++
		}
		if p.tokens[i].Kind == TokPunct && p.tokens[i].Val == ")" {
			depth--
			if depth == 0 && i+1 < len(p.tokens) {
				next := p.tokens[i+1]
				if next.Kind == TokPunct && next.Val == "=>" {
					return true
				}
				// TS: ): ReturnType =>
				if next.Kind == TokPunct && next.Val == ":" {
					for j := i + 2; j < len(p.tokens) && j < i+10; j++ {
						if p.tokens[j].Kind == TokPunct && p.tokens[j].Val == "=>" {
							return true
						}
					}
				}
			}
			return false
		}
	}
	return false
}

func (p *parser) parseFuncDecl(cls *ir.Class) {
	if p.peekIdent("async") {
		p.advance()
	}
	p.advance() // 'function'
	if p.peek().Kind != TokIdent {
		p.skipToSemicolon()
		return
	}
	name := p.peek().Val
	line := p.peek().Line
	col := p.peek().Col
	p.advance()

	fn := p.parseFuncBody(cls, name, line, col)
	if fn != nil {
		cls.Methods = append(cls.Methods, fn)
	}
}

func (p *parser) parseClassDecl(cls *ir.Class) {
	p.advance() // 'class'
	if p.peek().Kind != TokIdent {
		return
	}
	className := p.peek().Val
	p.advance()

	// Skip extends / implements.
	for !p.eof() && !p.peekPunct("{") {
		p.advance()
	}
	if !p.peekPunct("{") {
		return
	}
	p.advance() // '{'

	innerCls := &ir.Class{
		Name: className,
		FQN:  p.mod.Path + "." + className,
	}
	p.mod.Classes = append(p.mod.Classes, innerCls)

	// Parse class body.
	depth := 1
	for !p.eof() && depth > 0 {
		if p.peekPunct("}") {
			depth--
			p.advance()
			continue
		}
		if p.peekPunct("{") {
			depth++
			p.advance()
			continue
		}
		// Method.
		if p.peek().Kind == TokIdent && !isJSKeyword(p.peek().Val) {
			name := p.peek().Val
			line := p.peek().Line
			col := p.peek().Col
			p.advance()
			if p.peekPunct("(") {
				fn := p.parseFuncBody(innerCls, name, line, col)
				if fn != nil {
					innerCls.Methods = append(innerCls.Methods, fn)
				}
				continue
			}
		}
		p.advance()
	}
}

func (p *parser) parseFuncBody(cls *ir.Class, name string, line, col int) *ir.Function {
	fn := &ir.Function{
		Name:       name,
		FQN:        cls.FQN + "." + name,
		ReturnType: ir.Unknown(),
		Loc:        ir.Location{Line: line, Column: col},
	}
	block := &ir.BasicBlock{ID: 0}
	fn.Blocks = []*ir.BasicBlock{block}
	ctx := &funcCtx{fn: fn, block: block, locals: map[string]ir.ValueID{}, localType: map[string]string{}, nextValue: 1}

	// Skip to opening '(' of params.
	if p.peekIdent("async") {
		p.advance()
	}
	if p.peekIdent("function") {
		p.advance()
	}
	if p.peekPunct("(") {
		p.seedParams(ctx)
	}

	// Skip to '=>' or '{'.
	for !p.eof() && !p.peekPunct("{") && !p.peekPunct("=>") {
		p.advance()
	}
	if p.peekPunct("=>") {
		p.advance()
	}
	if !p.peekPunct("{") {
		// Single-expression arrow function — skip.
		p.skipToSemicolon()
		return fn
	}
	p.advance() // '{'

	p.funcStack = append(p.funcStack, ctx)
	p.parseBlock(ctx, 1)
	if len(p.funcStack) > 0 {
		p.funcStack = p.funcStack[:len(p.funcStack)-1]
	}
	return fn
}

func (p *parser) seedParams(ctx *funcCtx) {
	p.advance() // '('
	for !p.eof() && !p.peekPunct(")") {
		if p.peek().Kind == TokIdent && !isJSKeyword(p.peek().Val) {
			name := p.peek().Val
			v := ctx.newValue()
			ctx.locals[name] = v
			ctx.fn.Parameters = append(ctx.fn.Parameters, ir.Parameter{
				Name:  name,
				Type:  ir.Unknown(),
				Value: v,
			})
		}
		p.advance()
	}
	if p.peekPunct(")") {
		p.advance()
	}
}

func (p *parser) parseBlock(ctx *funcCtx, depth int) {
	for !p.eof() && depth > 0 {
		if p.peekPunct("}") {
			depth--
			p.advance()
			continue
		}
		if p.peekPunct("{") {
			depth++
			p.advance()
			continue
		}

		t := p.peek()

		// Variable declarations inside function.
		if t.Kind == TokIdent && (t.Val == "const" || t.Val == "let" || t.Val == "var") {
			p.parseLocalDecl(ctx)
			continue
		}

		// Call detection: IDENT(...) or IDENT.IDENT(...)
		if t.Kind == TokIdent && !isJSKeyword(t.Val) {
			p.tryEmitCall(ctx)
			continue
		}

		p.advance()
	}
}

func (p *parser) parseLocalDecl(ctx *funcCtx) {
	p.advance() // const/let/var
	if p.peek().Kind != TokIdent {
		p.skipToSemicolon()
		return
	}
	varName := p.peek().Val
	varLine := p.peek().Line
	varCol := p.peek().Col
	p.advance()

	// Skip type annotations.
	if p.peekPunct(":") {
		for !p.eof() && !p.peekPunct("=") && !p.peekPunct(";") && !p.peekPunct("}") {
			p.advance()
		}
	}

	if !p.peekPunct("=") {
		return
	}
	p.advance() // '='

	// String literal (possibly with concatenation: "..." + expr).
	if p.peek().Kind == TokString {
		strVal := p.peek().Val
		val := ctx.newValue()
		ctx.emit(&ir.Instruction{
			Op: ir.OpConst, Result: val,
			ResultType: ir.Nominal("string"),
			Operands:   []ir.Operand{ir.ConstString(strVal)},
			Loc:        ir.Location{Line: p.peek().Line, Column: p.peek().Col},
		})
		p.advance()
		// Handle string concatenation: "..." + id + ...
		// If any concatenated operand is a tainted local, the result
		// carries its taint via a BinOp instruction.
		resultVal := val
		for p.peekPunct("+") {
			p.advance() // '+'
			if p.peek().Kind == TokIdent {
				rhsName := p.peek().Val
				if rhsVal, ok := ctx.locals[rhsName]; ok {
					concatResult := ctx.newValue()
					ctx.emit(&ir.Instruction{
						Op: ir.OpBinOp, Result: concatResult,
						ResultType: ir.Nominal("string"),
						Operands:   []ir.Operand{ir.ValueRef(resultVal), ir.ValueRef(rhsVal)},
						Loc:        ir.Location{Line: p.peek().Line, Column: p.peek().Col},
					})
					resultVal = concatResult
				}
				p.advance()
			} else if p.peek().Kind == TokString {
				p.advance() // skip literal part of concat
			} else {
				break
			}
		}
		ctx.locals[varName] = resultVal
		ctx.emit(&ir.Instruction{
			Op:       ir.OpStore,
			Operands: []ir.Operand{ir.ConstString(varName), ir.ValueRef(resultVal)},
			Loc:      ir.Location{Line: varLine, Column: varCol},
		})
		return
	}

	// Expression: try to emit calls or resolve property chains.
	if p.peek().Kind == TokIdent && !isJSKeyword(p.peek().Val) {
		// Check for req.query.X / req.body.X / req.params.X property access.
		firstIdent := p.peek().Val
		if (firstIdent == "req" || firstIdent == "request") && p.peekAtKind(1, TokPunct) {
			// Walk the chain.
			chainStart := p.pos
			var chain []string
			chain = append(chain, firstIdent)
			p.advance()
			for p.peekPunct(".") && p.peekAtKind(1, TokIdent) {
				p.advance() // '.'
				chain = append(chain, p.peek().Val)
				p.advance()
			}
			if len(chain) >= 2 && (chain[1] == "query" || chain[1] == "body" || chain[1] == "params") {
				calleeFQN := chain[0] + "." + chain[1]
				result := ctx.newValue()
				ctx.emit(&ir.Instruction{
					Op: ir.OpCall, Result: result, ResultType: ir.Unknown(),
					ReceiverType: chain[0], Callee: chain[1], CalleeFQN: calleeFQN,
					Loc: ir.Location{Line: p.tokens[chainStart].Line, Column: p.tokens[chainStart].Col},
				})
				ctx.locals[varName] = result
				ctx.emit(&ir.Instruction{
					Op:       ir.OpStore,
					Operands: []ir.Operand{ir.ConstString(varName), ir.ValueRef(result)},
					Loc:      ir.Location{Line: varLine, Column: varCol},
				})
				p.skipToSemicolon()
				return
			}
			p.pos = chainStart // rewind
		}

		callVal := p.tryEmitCallExpr(ctx)
		if callVal != 0 {
			ctx.locals[varName] = callVal
			ctx.emit(&ir.Instruction{
				Op:       ir.OpStore,
				Operands: []ir.Operand{ir.ConstString(varName), ir.ValueRef(callVal)},
				Loc:      ir.Location{Line: varLine, Column: varCol},
			})
			return
		}
	}

	p.skipToSemicolon()
}

func (p *parser) tryEmitCall(ctx *funcCtx) {
	// Walk forward through dot-chain to find IDENT(...).
	startPos := p.pos
	var chain []string
	chain = append(chain, p.peek().Val)
	p.advance()

	for p.peekPunct(".") && p.peekAtKind(1, TokIdent) {
		p.advance() // '.'
		chain = append(chain, p.peek().Val)
		p.advance()
	}

	if !p.peekPunct("(") {
		// Check for property access on known HTTP sources: req.query.X, req.body.X, req.params.X
		// Emit these as synthetic source calls so the taint engine sees them.
		if len(chain) >= 2 && (chain[0] == "req" || chain[0] == "request") {
			prop := chain[1]
			if prop == "query" || prop == "body" || prop == "params" {
				calleeFQN := chain[0] + "." + prop
				result := ctx.newValue()
				ctx.emit(&ir.Instruction{
					Op: ir.OpCall, Result: result, ResultType: ir.Unknown(),
					ReceiverType: chain[0], Callee: prop, CalleeFQN: calleeFQN,
					Loc: ir.Location{Line: p.tokens[startPos].Line, Column: p.tokens[startPos].Col},
				})
				// If this is `const X = req.query.Y`, the caller will capture the result via Store.
				if len(p.funcStack) > 0 {
					// Register the whole chain as tainted via the result value.
					fullName := strings.Join(chain, ".")
					p.funcStack[len(p.funcStack)-1].locals[fullName] = result
					if len(chain) > 2 {
						p.funcStack[len(p.funcStack)-1].locals[chain[len(chain)-1]] = result
					}
				}
			}
		}
		// Not a call — might be an assignment.
		if p.peekPunct("=") && !p.peekPunct("==") {
			p.advance() // '='
			p.skipToSemicolon()
		}
		return
	}

	callee := chain[len(chain)-1]
	receiverChain := chain[:len(chain)-1]
	receiverFQN := ""
	calleeFQN := ""

	if len(receiverChain) > 0 {
		first := receiverChain[0]
		if mod, ok := p.imports[first]; ok {
			receiverFQN = mod
		} else {
			receiverFQN = strings.Join(receiverChain, ".")
		}
		calleeFQN = receiverFQN + "." + callee
	} else {
		// Bare call: check if the function name comes from a destructured import.
		// e.g., const { exec } = require("child_process") → exec(...) → child_process.exec
		if mod, ok := p.imports[callee]; ok {
			receiverFQN = mod
			calleeFQN = mod + "." + callee
		}
	}

	// Scan args.
	args := p.scanArgs()
	line := p.tokens[startPos].Line
	col := p.tokens[startPos].Col

	result := ctx.newValue()
	inst := &ir.Instruction{
		Op:           ir.OpCall,
		Result:       result,
		ResultType:   ir.Unknown(),
		ReceiverType: receiverFQN,
		Callee:       callee,
		CalleeFQN:    calleeFQN,
		Operands:     args,
		Loc:          ir.Location{Line: line, Column: col},
	}
	ctx.emit(inst)
}

func (p *parser) tryEmitCallExpr(ctx *funcCtx) ir.ValueID {
	startPos := p.pos
	var chain []string
	chain = append(chain, p.peek().Val)
	p.advance()

	for p.peekPunct(".") && p.peekAtKind(1, TokIdent) {
		p.advance()
		chain = append(chain, p.peek().Val)
		p.advance()
	}

	if !p.peekPunct("(") {
		p.pos = startPos
		return 0
	}

	callee := chain[len(chain)-1]
	receiverChain := chain[:len(chain)-1]
	receiverFQN := ""
	calleeFQN := ""
	if len(receiverChain) > 0 {
		first := receiverChain[0]
		if mod, ok := p.imports[first]; ok {
			receiverFQN = mod
		} else {
			receiverFQN = strings.Join(receiverChain, ".")
		}
		calleeFQN = receiverFQN + "." + callee
	}

	args := p.scanArgs()
	line := p.tokens[startPos].Line
	col := p.tokens[startPos].Col

	result := ctx.newValue()
	ctx.emit(&ir.Instruction{
		Op: ir.OpCall, Result: result, ResultType: ir.Unknown(),
		ReceiverType: receiverFQN, Callee: callee, CalleeFQN: calleeFQN,
		Operands: args, Loc: ir.Location{Line: line, Column: col},
	})
	return result
}

func (p *parser) scanArgs() []ir.Operand {
	if !p.peekPunct("(") {
		return nil
	}
	p.advance() // '('
	var args []ir.Operand
	depth := 1
	for !p.eof() && depth > 0 {
		t := p.peek()
		if t.Kind == TokPunct && t.Val == "(" {
			depth++
		} else if t.Kind == TokPunct && t.Val == ")" {
			depth--
			if depth == 0 {
				p.advance()
				return args
			}
		}
		if depth == 1 {
			if t.Kind == TokString {
				args = append(args, ir.ConstString(t.Val))
			} else if t.Kind == TokIdent {
				// Try to resolve as a local variable.
				if len(p.funcStack) > 0 {
					ctx := p.funcStack[len(p.funcStack)-1]
					if v, ok := ctx.locals[t.Val]; ok {
						args = append(args, ir.ValueRef(v))
					}
				}
			}
		}
		p.advance()
	}
	return args
}

func (p *parser) getClinitFunc(cls *ir.Class) *funcCtx {
	for _, m := range cls.Methods {
		if m.Name == "<module-init>" {
			block := m.Blocks[0]
			return &funcCtx{fn: m, block: block, locals: map[string]ir.ValueID{}, localType: map[string]string{}, nextValue: 1}
		}
	}
	fn := &ir.Function{
		Name: "<module-init>", FQN: cls.FQN + ".<module-init>",
		ReturnType: ir.Unknown(),
	}
	block := &ir.BasicBlock{ID: 0}
	fn.Blocks = []*ir.BasicBlock{block}
	cls.Methods = append(cls.Methods, fn)
	return &funcCtx{fn: fn, block: block, locals: map[string]ir.ValueID{}, localType: map[string]string{}, nextValue: 1}
}

func (p *parser) skipToSemicolon() {
	depth := 0
	for !p.eof() {
		t := p.peek()
		if t.Kind == TokPunct {
			switch t.Val {
			case "{":
				depth++
			case "}":
				if depth == 0 {
					return
				}
				depth--
			case ";":
				if depth == 0 {
					p.advance()
					return
				}
			}
		}
		p.advance()
	}
}

// --- Helpers ---

func (p *parser) eof() bool    { return p.pos >= len(p.tokens) || p.tokens[p.pos].Kind == TokEOF }
func (p *parser) peek() Token  { if p.pos < len(p.tokens) { return p.tokens[p.pos] }; return Token{Kind: TokEOF} }
func (p *parser) advance()     { if p.pos < len(p.tokens) { p.pos++ } }
func (p *parser) peekPunct(v string) bool { t := p.peek(); return t.Kind == TokPunct && t.Val == v }
func (p *parser) peekIdent(v string) bool { t := p.peek(); return t.Kind == TokIdent && t.Val == v }
func (p *parser) peekAtKind(offset int, kind TokenKind) bool {
	i := p.pos + offset
	if i < 0 || i >= len(p.tokens) { return false }
	return p.tokens[i].Kind == kind
}

func isJSKeyword(s string) bool {
	_, ok := jsKeywords[s]
	return ok
}

var jsKeywords = map[string]struct{}{
	"if": {}, "else": {}, "for": {}, "while": {}, "do": {},
	"switch": {}, "case": {}, "break": {}, "continue": {},
	"return": {}, "throw": {}, "try": {}, "catch": {}, "finally": {},
	"new": {}, "delete": {}, "typeof": {}, "instanceof": {},
	"void": {}, "in": {}, "of": {}, "with": {},
	"true": {}, "false": {}, "null": {}, "undefined": {},
	"this": {}, "super": {}, "yield": {}, "await": {},
	"debugger": {},
}
