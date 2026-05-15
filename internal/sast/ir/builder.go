package ir

import (
	"crypto/sha256"
	"encoding/hex"
)

// ModuleBuilder is a small ergonomic helper for constructing a Module
// programmatically. It's used by:
//
//   1. The Chunk SAST-1 fixture layer (internal/sast/fixtures), which
//      hand-builds IR that stands in for a real Java parser until Chunk
//      SAST-2 lands the JVM sidecar.
//   2. Unit tests throughout the engine.
//   3. The Java sidecar's Go-side receiver, later, when it decodes JSON IR
//      from the sidecar and materializes Module objects.
//
// Keeping the builder separate from the types keeps ir.go small and focused.
type ModuleBuilder struct {
	mod *Module
}

// NewModule starts building a module. The ID is derived deterministically
// from the path so two scans of the same artifact produce identical module
// IDs (which in turn keep finding fingerprints stable across scans).
func NewModule(path, language string) *ModuleBuilder {
	id := sha256.Sum256([]byte(path))
	return &ModuleBuilder{
		mod: &Module{
			ID:       hex.EncodeToString(id[:]),
			Path:     path,
			Language: language,
		},
	}
}

// Package sets the module's declared package.
func (b *ModuleBuilder) Package(pkg string) *ModuleBuilder {
	b.mod.Package = pkg
	return b
}

// Import appends a fully-qualified import.
func (b *ModuleBuilder) Import(fqns ...string) *ModuleBuilder {
	b.mod.Imports = append(b.mod.Imports, fqns...)
	return b
}

// Class creates a new Class, adds it to the module, and returns a
// ClassBuilder for further population.
func (b *ModuleBuilder) Class(simpleName, fqn string) *ClassBuilder {
	c := &Class{Name: simpleName, FQN: fqn}
	b.mod.Classes = append(b.mod.Classes, c)
	return &ClassBuilder{mod: b, class: c}
}

// Build finalizes the module.
func (b *ModuleBuilder) Build() *Module {
	return b.mod
}

// ClassBuilder populates a Class.
type ClassBuilder struct {
	mod   *ModuleBuilder
	class *Class
}

// Extends sets the parent class FQN.
func (b *ClassBuilder) Extends(fqn string) *ClassBuilder {
	b.class.Extends = fqn
	return b
}

// Method creates a new Function on this class and returns a FunctionBuilder.
// The FQN is computed from the class FQN + method name; this does not include
// parameter-type mangling yet (that lands with the real Java frontend).
func (b *ClassBuilder) Method(name string, returnType Type, params ...Parameter) *FunctionBuilder {
	fn := &Function{
		Name:       name,
		FQN:        b.class.FQN + "." + name,
		Parameters: params,
		ReturnType: returnType,
	}
	b.class.Methods = append(b.class.Methods, fn)
	return &FunctionBuilder{class: b, fn: fn, nextValue: ValueID(len(params) + 1), nextBlock: 0}
}

// Done returns the parent ModuleBuilder.
func (b *ClassBuilder) Done() *ModuleBuilder {
	return b.mod
}

// FunctionBuilder populates a Function's basic blocks and instructions.
type FunctionBuilder struct {
	class     *ClassBuilder
	fn        *Function
	current   *BasicBlock
	nextValue ValueID
	nextBlock BlockID
}

// EntryBlock creates (if not already) and returns the entry basic block.
func (b *FunctionBuilder) EntryBlock() *FunctionBuilder {
	if b.current == nil {
		blk := &BasicBlock{ID: b.nextBlock}
		b.nextBlock++
		b.fn.Blocks = append(b.fn.Blocks, blk)
		b.current = blk
	}
	return b
}

// NewValue allocates a fresh SSA value ID within this function.
func (b *FunctionBuilder) NewValue() ValueID {
	v := b.nextValue
	b.nextValue++
	return v
}

// Call emits a Call instruction with the given receiver type, simple callee,
// fully-qualified callee, result type, and operands. Chainable. Use Last() to
// grab the instruction pointer if you need its result ValueID for subsequent
// operands.
func (b *FunctionBuilder) Call(receiverType, callee, calleeFQN string, resultType Type, loc Location, ops ...Operand) *FunctionBuilder {
	b.EntryBlock()
	result := ValueID(0)
	if resultType.Kind != KindUnknown || resultType.Name != "" {
		result = b.NewValue()
	}
	inst := &Instruction{
		Op:           OpCall,
		Result:       result,
		ResultType:   resultType,
		Operands:     ops,
		ReceiverType: receiverType,
		Callee:       callee,
		CalleeFQN:    calleeFQN,
		Loc:          loc,
	}
	b.current.Instructions = append(b.current.Instructions, inst)
	return b
}

// CallWithArgText is like Call but also records the verbatim source text of
// each operand. argText must be the same length as ops; pass empty strings
// for operands whose source span is unavailable. Frontends that have access
// to AST node spans should prefer this; pure constant calls without spans
// can keep using Call.
func (b *FunctionBuilder) CallWithArgText(receiverType, callee, calleeFQN string, resultType Type, loc Location, ops []Operand, argText []string) *FunctionBuilder {
	b.EntryBlock()
	result := ValueID(0)
	if resultType.Kind != KindUnknown || resultType.Name != "" {
		result = b.NewValue()
	}
	if argText != nil && len(argText) != len(ops) {
		fixed := make([]string, len(ops))
		copy(fixed, argText)
		argText = fixed
	}
	inst := &Instruction{
		Op:            OpCall,
		Result:        result,
		ResultType:    resultType,
		Operands:      ops,
		ReceiverType:  receiverType,
		Callee:        callee,
		CalleeFQN:     calleeFQN,
		Loc:           loc,
		ArgSourceText: argText,
	}
	b.current.Instructions = append(b.current.Instructions, inst)
	return b
}

// Last returns the most recently emitted instruction in the current block,
// or nil if the block is empty. Useful when a caller needs to capture a
// result ValueID for a subsequent operand.
func (b *FunctionBuilder) Last() *Instruction {
	if b.current == nil || len(b.current.Instructions) == 0 {
		return nil
	}
	return b.current.Instructions[len(b.current.Instructions)-1]
}

// Return emits a void return.
func (b *FunctionBuilder) Return(loc Location) *FunctionBuilder {
	b.EntryBlock()
	b.current.Instructions = append(b.current.Instructions, &Instruction{
		Op:  OpReturn,
		Loc: loc,
	})
	return b
}

// Done returns the parent ClassBuilder.
func (b *FunctionBuilder) Done() *ClassBuilder {
	return b.class
}

// ConstString is a convenience constructor for a string-literal operand.
func ConstString(s string) Operand {
	return Operand{Kind: OperandConstString, StrVal: s}
}

// ConstInt is a convenience constructor for an integer-literal operand.
func ConstInt(i int64) Operand {
	return Operand{Kind: OperandConstInt, IntVal: i}
}

// ValueRef is a convenience constructor for a value-reference operand.
func ValueRef(v ValueID) Operand {
	return Operand{Kind: OperandValue, Value: v}
}

// At is a short alias for constructing a Location.
func At(line, col int) Location {
	return Location{Line: line, Column: col}
}
