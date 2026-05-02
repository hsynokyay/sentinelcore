package python

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
)

// Parse tokenizes and parses a Python file into SentinelIR.
func Parse(relPath string, src []byte) *ir.Module {
	tokens := Tokenize(src)
	p := &parser{
		tokens:     tokens,
		src:        src,
		lineStarts: computeLineStarts(src),
		imports:    map[string]string{},
		mod: &ir.Module{
			ID:       moduleID(relPath),
			Path:     relPath,
			Language: "python",
		},
	}
	p.run()
	return p.mod
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

// callSiteText reconstructs the verbatim source text of a call expression
// from the token at startPos through the most recently consumed token
// (which should be the closing ')'). Returns "" if positions are invalid.
func (p *parser) callSiteText(startPos int) string {
	if startPos < 0 || startPos >= len(p.tokens) || p.pos < 1 || p.pos-1 >= len(p.tokens) {
		return ""
	}
	start := p.tokens[startPos]
	end := p.tokens[p.pos-1]
	endCol := end.Col + len(end.Val)
	return p.srcSpan(start.Line, start.Col, end.Line, endCol)
}

func moduleID(relPath string) string {
	sum := sha256.Sum256([]byte(relPath))
	return hex.EncodeToString(sum[:])
}

type parser struct {
	tokens     []Token
	pos        int
	src        []byte
	lineStarts []int
	mod        *ir.Module
	imports    map[string]string
	funcStack  []*funcCtx
}

type funcCtx struct {
	fn        *ir.Function
	block     *ir.BasicBlock
	locals    map[string]ir.ValueID
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
	cls := &ir.Class{Name: "<module>", FQN: p.mod.Path}
	p.mod.Classes = append(p.mod.Classes, cls)
	for !p.eof() {
		p.stepTopLevel(cls)
	}
}

func (p *parser) stepTopLevel(cls *ir.Class) {
	t := p.peek()
	if t.Kind == TokNewline {
		p.advance()
		return
	}
	// import / from ... import
	if t.Kind == TokIdent && (t.Val == "import" || t.Val == "from") {
		p.parseImport()
		return
	}
	// def function
	if t.Kind == TokIdent && t.Val == "def" {
		p.parseFuncDef(cls)
		return
	}
	// class
	if t.Kind == TokIdent && t.Val == "class" {
		p.parseClassDef(cls)
		return
	}
	// Module-level assignment (secrets detection)
	if t.Kind == TokIdent && p.peekAtKind(1, TokPunct) {
		if p.peekAtVal(1, "=") && p.peekAtKind(2, TokString) {
			varName := t.Val
			p.advance() // name
			p.advance() // =
			strVal := p.peek().Val
			clinit := p.getClinitFunc(cls)
			clinit.emit(&ir.Instruction{
				Op:       ir.OpStore,
				Operands: []ir.Operand{ir.ConstString(varName), ir.ConstString(strVal)},
				Loc:      ir.Location{Line: t.Line, Column: t.Col},
			})
			p.skipToNewline()
			return
		}
	}
	// Decorators
	if t.Kind == TokPunct && t.Val == "@" {
		p.skipToNewline()
		return
	}
	p.advance()
}

func (p *parser) parseImport() {
	if p.peekIdent("from") {
		p.advance() // from
		var modParts []string
		for p.peek().Kind == TokIdent && p.peek().Val != "import" {
			modParts = append(modParts, p.peek().Val)
			p.advance()
			if p.peekPunct(".") {
				p.advance()
			}
		}
		modName := strings.Join(modParts, ".")
		if p.peekIdent("import") {
			p.advance() // import
			for p.peek().Kind == TokIdent {
				name := p.peek().Val
				p.imports[name] = modName
				p.advance()
				if p.peekPunct(",") {
					p.advance()
				}
			}
		}
		p.mod.Imports = append(p.mod.Imports, modName)
	} else {
		p.advance() // import
		var modParts []string
		for p.peek().Kind == TokIdent {
			modParts = append(modParts, p.peek().Val)
			p.advance()
			if p.peekPunct(".") {
				p.advance()
			}
		}
		modName := strings.Join(modParts, ".")
		// import os → imports["os"] = "os"
		if len(modParts) > 0 {
			p.imports[modParts[0]] = modName
		}
		// import os as alias
		if p.peekIdent("as") {
			p.advance()
			if p.peek().Kind == TokIdent {
				p.imports[p.peek().Val] = modName
				p.advance()
			}
		}
		p.mod.Imports = append(p.mod.Imports, modName)
	}
	p.skipToNewline()
}

func (p *parser) parseFuncDef(cls *ir.Class) {
	p.advance() // def
	if p.peek().Kind != TokIdent {
		p.skipToNewline()
		return
	}
	name := p.peek().Val
	line := p.peek().Line
	col := p.peek().Col
	p.advance()

	fn := &ir.Function{
		Name:       name,
		FQN:        cls.FQN + "." + name,
		ReturnType: ir.Unknown(),
		Loc:        ir.Location{Line: line, Column: col},
	}
	block := &ir.BasicBlock{ID: 0}
	fn.Blocks = []*ir.BasicBlock{block}
	ctx := &funcCtx{fn: fn, block: block, locals: map[string]ir.ValueID{}, nextValue: 1}

	// Parse params.
	if p.peekPunct("(") {
		p.seedParams(ctx)
	}
	// Skip to colon.
	for !p.eof() && !p.peekPunct(":") && p.peek().Kind != TokNewline {
		p.advance()
	}
	if p.peekPunct(":") {
		p.advance()
	}
	p.skipToNewline()

	cls.Methods = append(cls.Methods, fn)
	p.funcStack = append(p.funcStack, ctx)
	p.parseBody(ctx)
	if len(p.funcStack) > 0 {
		p.funcStack = p.funcStack[:len(p.funcStack)-1]
	}
}

func (p *parser) seedParams(ctx *funcCtx) {
	p.advance() // (
	for !p.eof() && !p.peekPunct(")") {
		if p.peek().Kind == TokIdent && p.peek().Val != "self" && p.peek().Val != "cls" {
			name := p.peek().Val
			if !isPyKeyword(name) {
				v := ctx.newValue()
				ctx.locals[name] = v
				ctx.fn.Parameters = append(ctx.fn.Parameters, ir.Parameter{
					Name: name, Type: ir.Unknown(), Value: v,
				})
			}
		}
		p.advance()
	}
	if p.peekPunct(")") {
		p.advance()
	}
}

func (p *parser) parseClassDef(cls *ir.Class) {
	p.advance() // class
	if p.peek().Kind != TokIdent {
		return
	}
	className := p.peek().Val
	p.advance()
	// Skip bases.
	for !p.eof() && !p.peekPunct(":") && p.peek().Kind != TokNewline {
		p.advance()
	}
	if p.peekPunct(":") {
		p.advance()
	}
	p.skipToNewline()

	innerCls := &ir.Class{Name: className, FQN: p.mod.Path + "." + className}
	p.mod.Classes = append(p.mod.Classes, innerCls)
	// Parse class body — look for def statements.
	p.parseClassBody(innerCls)
}

func (p *parser) parseClassBody(cls *ir.Class) {
	// Simple heuristic: parse until we see a non-indented line or EOF.
	// Python's indentation is significant — we detect dedent by checking
	// if the first non-newline token on a line starts at column 1.
	for !p.eof() {
		if p.peek().Kind == TokNewline {
			p.advance()
			continue
		}
		// If the token is at column 1 and it's not a decorator, we've dedented.
		if p.peek().Col <= 1 && p.peek().Val != "@" {
			return
		}
		if p.peekIdent("def") {
			p.parseFuncDef(cls)
			continue
		}
		if p.peek().Kind == TokPunct && p.peek().Val == "@" {
			p.skipToNewline()
			continue
		}
		p.skipToNewline()
	}
}

func (p *parser) parseBody(ctx *funcCtx) {
	// Parse function body until dedent. Simple heuristic: body continues
	// while lines are indented (col > 1 for module-level funcs, or
	// col > method's col for class methods).
	baseCol := 4 // typical indent
	for !p.eof() {
		if p.peek().Kind == TokNewline {
			p.advance()
			continue
		}
		if p.peek().Col <= 1 {
			return
		}
		t := p.peek()

		// Local assignment: name = expr
		if t.Kind == TokIdent && !isPyKeyword(t.Val) && p.peekAtVal(1, "=") && !p.peekAtVal(1, "==") {
			p.parseAssignment(ctx)
			continue
		}

		// Call: name.method(...) or name(...)
		if t.Kind == TokIdent && !isPyKeyword(t.Val) {
			p.tryEmitCall(ctx)
			continue
		}

		// 'with' statement: with open(...) as f:
		if t.Kind == TokIdent && t.Val == "with" {
			p.advance() // 'with'
			if p.peek().Kind == TokIdent && !isPyKeyword(p.peek().Val) {
				p.tryEmitCall(ctx)
			} else {
				p.skipToNewline()
			}
			continue
		}

		// return with expression — handle both `return var` and `return call(...)`.
		if t.Kind == TokIdent && t.Val == "return" {
			p.advance()
			if p.peek().Kind == TokIdent && !isPyKeyword(p.peek().Val) {
				// Try to emit as a call expression first (return pickle.loads(x)).
				callVal := p.tryEmitCallExpr(ctx)
				if callVal != 0 {
					ctx.emit(&ir.Instruction{
						Op: ir.OpReturn,
						Operands: []ir.Operand{ir.ValueRef(callVal)},
						Loc: ir.Location{Line: t.Line, Column: t.Col},
					})
					p.skipToNewline()
					continue
				}
				// Simple variable return.
				if v, ok := ctx.locals[p.peek().Val]; ok {
					ctx.emit(&ir.Instruction{
						Op: ir.OpReturn,
						Operands: []ir.Operand{ir.ValueRef(v)},
						Loc: ir.Location{Line: t.Line, Column: t.Col},
					})
				}
			}
			p.skipToNewline()
			continue
		}

		_ = baseCol
		p.skipToNewline()
	}
}

func (p *parser) parseAssignment(ctx *funcCtx) {
	varName := p.peek().Val
	varLine := p.peek().Line
	varCol := p.peek().Col
	p.advance() // name
	p.advance() // =

	// String literal (possibly with concatenation).
	if p.peek().Kind == TokString {
		strVal := p.peek().Val
		val := ctx.newValue()
		ctx.emit(&ir.Instruction{
			Op: ir.OpConst, Result: val, ResultType: ir.Nominal("str"),
			Operands: []ir.Operand{ir.ConstString(strVal)},
			Loc:      ir.Location{Line: p.peek().Line, Column: p.peek().Col},
		})
		p.advance()
		// Handle "..." + var concatenation.
		resultVal := val
		for p.peekPunct("+") {
			p.advance()
			if p.peek().Kind == TokIdent {
				if rhsVal, ok := ctx.locals[p.peek().Val]; ok {
					concatResult := ctx.newValue()
					ctx.emit(&ir.Instruction{
						Op: ir.OpBinOp, Result: concatResult, ResultType: ir.Nominal("str"),
						Operands: []ir.Operand{ir.ValueRef(resultVal), ir.ValueRef(rhsVal)},
						Loc:      ir.Location{Line: p.peek().Line, Column: p.peek().Col},
					})
					resultVal = concatResult
				}
				p.advance()
			} else if p.peek().Kind == TokString {
				p.advance()
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
		p.skipToNewline()
		return
	}

	// f-string: f"...{var}..." — treat as tainted if interpolating a tainted var.
	if p.peek().Kind == TokIdent && p.peek().Val == "f" && p.peekAtKind(1, TokString) {
		p.advance() // f
		// The f-string is tokenized as a regular string. Check if any
		// interpolated variable is tainted.
		fstr := p.peek().Val
		p.advance()
		for localName, localVal := range ctx.locals {
			if strings.Contains(fstr, "{"+localName+"}") || strings.Contains(fstr, "{"+localName) {
				ctx.locals[varName] = localVal
				ctx.emit(&ir.Instruction{
					Op:       ir.OpStore,
					Operands: []ir.Operand{ir.ConstString(varName), ir.ValueRef(localVal)},
					Loc:      ir.Location{Line: varLine, Column: varCol},
				})
				break
			}
		}
		p.skipToNewline()
		return
	}

	// Property access: request.args.get("key") or request.form["key"]
	if p.peek().Kind == TokIdent {
		callVal := p.tryEmitCallExpr(ctx)
		if callVal != 0 {
			ctx.locals[varName] = callVal
			ctx.emit(&ir.Instruction{
				Op:       ir.OpStore,
				Operands: []ir.Operand{ir.ConstString(varName), ir.ValueRef(callVal)},
				Loc:      ir.Location{Line: varLine, Column: varCol},
			})
			p.skipToNewline()
			return
		}
	}

	p.skipToNewline()
}

func (p *parser) tryEmitCall(ctx *funcCtx) {
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
		if p.peekPunct("=") && !p.peekPunct("==") {
			p.skipToNewline()
		} else {
			p.skipToNewline()
		}
		return
	}

	line := p.tokens[startPos].Line
	col := p.tokens[startPos].Col

	// Flask source pattern for standalone calls.
	if len(chain) >= 3 && chain[0] == "request" {
		prop := chain[1]
		if prop == "args" || prop == "form" || prop == "json" {
			srcFQN := chain[0] + "." + prop
			srcResult := ctx.newValue()
			ctx.emit(&ir.Instruction{
				Op: ir.OpCall, Result: srcResult, ResultType: ir.Unknown(),
				ReceiverType: chain[0], Callee: prop, CalleeFQN: srcFQN,
				Loc: ir.Location{Line: line, Column: col},
			})
			args := p.scanArgs(ctx)
			callText := p.callSiteText(startPos)
			callResult := ctx.newValue()
			ctx.emit(&ir.Instruction{
				Op: ir.OpCall, Result: callResult, ResultType: ir.Unknown(),
				ReceiverType: srcFQN, Callee: chain[len(chain)-1],
				CalleeFQN: srcFQN + "." + chain[len(chain)-1],
				Operands: append([]ir.Operand{ir.ValueRef(srcResult)}, args...),
				Loc:           ir.Location{Line: line, Column: col},
				ArgSourceText: []string{callText},
			})
			p.skipToNewline()
			return
		}
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
	} else if mod, ok := p.imports[callee]; ok {
		receiverFQN = mod
		calleeFQN = mod + "." + callee
	}
	args := p.scanArgs(ctx)
	callText := p.callSiteText(startPos)
	result := ctx.newValue()
	ctx.emit(&ir.Instruction{
		Op: ir.OpCall, Result: result, ResultType: ir.Unknown(),
		ReceiverType: receiverFQN, Callee: callee, CalleeFQN: calleeFQN,
		Operands:      args,
		Loc:           ir.Location{Line: line, Column: col},
		ArgSourceText: []string{callText},
	})
	p.skipToNewline()
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

	// Flask source pattern: request.args.get("key"), request.form.get("key")
	// Emit a synthetic source for request.args/form/json BEFORE the actual call.
	if len(chain) >= 3 && (chain[0] == "request") {
		prop := chain[1]
		if prop == "args" || prop == "form" || prop == "json" {
			srcFQN := chain[0] + "." + prop
			srcResult := ctx.newValue()
			ctx.emit(&ir.Instruction{
				Op: ir.OpCall, Result: srcResult, ResultType: ir.Unknown(),
				ReceiverType: chain[0], Callee: prop, CalleeFQN: srcFQN,
				Loc: ir.Location{Line: p.tokens[startPos].Line, Column: p.tokens[startPos].Col},
			})
			// The .get() call passes through the taint via the receiver.
			args := p.scanArgs(ctx)
			callText := p.callSiteText(startPos)
			callResult := ctx.newValue()
			ctx.emit(&ir.Instruction{
				Op: ir.OpCall, Result: callResult, ResultType: ir.Unknown(),
				ReceiverType: srcFQN, Callee: chain[len(chain)-1],
				CalleeFQN: srcFQN + "." + chain[len(chain)-1],
				Operands: append([]ir.Operand{ir.ValueRef(srcResult)}, args...),
				Loc:           ir.Location{Line: p.tokens[startPos].Line, Column: p.tokens[startPos].Col},
				ArgSourceText: []string{callText},
			})
			return callResult
		}
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
	} else if mod, ok := p.imports[callee]; ok {
		receiverFQN = mod
		calleeFQN = mod + "." + callee
	}
	args := p.scanArgs(ctx)
	callText := p.callSiteText(startPos)
	result := ctx.newValue()
	ctx.emit(&ir.Instruction{
		Op: ir.OpCall, Result: result, ResultType: ir.Unknown(),
		ReceiverType: receiverFQN, Callee: callee, CalleeFQN: calleeFQN,
		Operands:      args,
		Loc:           ir.Location{Line: p.tokens[startPos].Line, Column: p.tokens[startPos].Col},
		ArgSourceText: []string{callText},
	})
	return result
}

func (p *parser) scanArgs(ctx *funcCtx) []ir.Operand {
	if !p.peekPunct("(") {
		return nil
	}
	p.advance() // (
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
				if v, ok := ctx.locals[t.Val]; ok {
					args = append(args, ir.ValueRef(v))
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
			return &funcCtx{fn: m, block: m.Blocks[0], locals: map[string]ir.ValueID{}, nextValue: 1}
		}
	}
	fn := &ir.Function{Name: "<module-init>", FQN: cls.FQN + ".<module-init>", ReturnType: ir.Unknown()}
	block := &ir.BasicBlock{ID: 0}
	fn.Blocks = []*ir.BasicBlock{block}
	cls.Methods = append(cls.Methods, fn)
	return &funcCtx{fn: fn, block: block, locals: map[string]ir.ValueID{}, nextValue: 1}
}

func (p *parser) skipToNewline() {
	for !p.eof() && p.peek().Kind != TokNewline {
		p.advance()
	}
	if p.peek().Kind == TokNewline {
		p.advance()
	}
}

// --- Helpers ---

func (p *parser) eof() bool             { return p.pos >= len(p.tokens) || p.tokens[p.pos].Kind == TokEOF }
func (p *parser) peek() Token           { if p.pos < len(p.tokens) { return p.tokens[p.pos] }; return Token{Kind: TokEOF} }
func (p *parser) advance()              { if p.pos < len(p.tokens) { p.pos++ } }
func (p *parser) peekPunct(v string) bool { return p.peek().Kind == TokPunct && p.peek().Val == v }
func (p *parser) peekIdent(v string) bool { return p.peek().Kind == TokIdent && p.peek().Val == v }
func (p *parser) peekAtKind(offset int, kind TokenKind) bool {
	i := p.pos + offset; if i < 0 || i >= len(p.tokens) { return false }; return p.tokens[i].Kind == kind
}
func (p *parser) peekAtVal(offset int, val string) bool {
	i := p.pos + offset; if i < 0 || i >= len(p.tokens) { return false }; return p.tokens[i].Val == val
}

func isPyKeyword(s string) bool { _, ok := pyKeywords[s]; return ok }
var pyKeywords = map[string]struct{}{
	"if": {}, "elif": {}, "else": {}, "for": {}, "while": {},
	"def": {}, "class": {}, "return": {}, "yield": {}, "import": {},
	"from": {}, "as": {}, "with": {}, "try": {}, "except": {},
	"finally": {}, "raise": {}, "pass": {}, "break": {}, "continue": {},
	"and": {}, "or": {}, "not": {}, "in": {}, "is": {},
	"True": {}, "False": {}, "None": {}, "lambda": {}, "del": {},
	"global": {}, "nonlocal": {}, "assert": {}, "async": {}, "await": {},
}
