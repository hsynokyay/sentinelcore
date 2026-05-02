// Package ir defines SentinelIR — the language-agnostic intermediate
// representation the SAST analysis core operates on.
//
// Every language frontend (Java in the MVP slice; JS/TS, Python, and C# in
// later phases) emits SentinelIR. The rule engine, taint engine, call-graph
// builder, and evidence chain builder are all written against SentinelIR, not
// against any language-specific AST. This is the single most important
// architectural decision in the SAST engine — it lets one analysis core
// serve every language we ever add, and it makes rule authoring tractable.
//
// The IR is a typed SSA-friendly CFG: every function is a list of basic
// blocks, every block is a list of instructions, every instruction produces
// at most one typed SSA value. Chunk SAST-1 deliberately keeps the opcode
// set small (Const/Load/Store/Call/Return/Branch) — just enough to support
// AST-local rule matching. Later chunks add Phi nodes (for full SSA), GEP
// (field access), and taint-propagation-aware opcodes.
package ir

// Module is a single source compilation unit — conceptually one .java file
// today, one .ts file later. Modules are the unit of parse caching: a module
// is re-parsed iff its content SHA-256 changes.
type Module struct {
	ID       string    `json:"id"`                 // sha256 of the artifact-relative path
	Path     string    `json:"path"`               // artifact-relative path, e.g. "src/main/java/com/example/Foo.java"
	Language string    `json:"language"`           // "java"
	Package  string    `json:"package,omitempty"`  // "com.example"
	Imports  []string  `json:"imports,omitempty"`  // fully-qualified imports
	Classes  []*Class  `json:"classes,omitempty"`
}

// Class is a Java class, interface, or enum. Nested classes are flattened
// into the owning module's Classes list with a dotted FQN.
type Class struct {
	Name       string      `json:"name"`                 // simple name, "FooController"
	FQN        string      `json:"fqn"`                  // fully-qualified, "com.example.FooController"
	Extends    string      `json:"extends,omitempty"`    // FQN of parent class
	Implements []string    `json:"implements,omitempty"` // FQNs of implemented interfaces
	Methods    []*Function `json:"methods,omitempty"`
	Fields     []*Field    `json:"fields,omitempty"`
}

// Field is a class field. Used by rules that check for field-level patterns
// (e.g. hardcoded credentials in static fields).
type Field struct {
	Name string   `json:"name"`
	Type Type     `json:"type"`
	Loc  Location `json:"loc"`
}

// Function is a method or constructor. The FQN is the unique identifier used
// by the call graph and the summary cache:
// "com.example.FooController.handleLogin(java.lang.String,java.lang.String)".
type Function struct {
	Name       string        `json:"name"`       // simple name
	FQN        string        `json:"fqn"`        // fully-qualified with parameter types
	Parameters []Parameter   `json:"parameters,omitempty"`
	ReturnType Type          `json:"return_type"`
	Blocks     []*BasicBlock `json:"blocks,omitempty"`
	Loc        Location      `json:"loc"`
}

// Parameter is a formal parameter of a Function. Parameters receive SSA
// ValueIDs starting at 1 (0 is reserved for the implicit receiver `this`
// when the function is an instance method).
type Parameter struct {
	Name  string  `json:"name"`
	Type  Type    `json:"type"`
	Value ValueID `json:"value"`
}

// BlockID is a basic-block identifier, unique within a Function.
type BlockID int

// ValueID is an SSA value identifier, unique within a Function.
type ValueID int

// BasicBlock is a maximal straight-line sequence of instructions with a
// single entry point and explicit successor edges. The last instruction in a
// block is always a terminator (Branch, Return, or Throw in later chunks).
type BasicBlock struct {
	ID           BlockID        `json:"id"`
	Instructions []*Instruction `json:"instructions"`
	Successors   []BlockID      `json:"successors,omitempty"`
}

// Opcode enumerates the SentinelIR instruction set. Chunk SAST-1 only uses
// Call, Const, Load, Store, and Return — the other opcodes are reserved for
// later chunks so the rule engine can already pattern-match them without
// frontend rework when the taint engine lands.
type Opcode string

const (
	OpConst   Opcode = "const"   // materialize a constant literal
	OpLoad    Opcode = "load"    // read from local/field
	OpStore   Opcode = "store"   // write to local/field
	OpCall    Opcode = "call"    // function/method invocation
	OpNew     Opcode = "new"     // object construction
	OpReturn  Opcode = "return"  // terminator: return from function
	OpBranch  Opcode = "branch"  // terminator: unconditional/conditional jump
	OpBinOp   Opcode = "binop"    // binary operation (e.g. string concat via +)
	OpPhi     Opcode = "phi"      // SSA phi (reserved for later)
	OpExtCall Opcode = "ext_call" // call into unanalyzed/unresolved code
)

// Instruction is a single IR operation. Call instructions are the most
// information-dense: they carry the receiver type (for virtual-call resolution
// during call-graph construction), the callee's simple name, the callee's
// fully-qualified name if resolved, and the operand list.
type Instruction struct {
	Op         Opcode    `json:"op"`
	Result     ValueID   `json:"result,omitempty"`      // 0 if the instruction has no result
	ResultType Type      `json:"result_type,omitempty"`
	Operands   []Operand `json:"operands,omitempty"`

	// Call/ExtCall/New-specific fields.
	ReceiverType string `json:"receiver_type,omitempty"` // FQN of the receiver's declared type
	Callee       string `json:"callee,omitempty"`        // simple method name, e.g. "getInstance"
	CalleeFQN    string `json:"callee_fqn,omitempty"`    // fully qualified, e.g. "javax.crypto.Cipher.getInstance"

	Loc Location `json:"loc"`

	// ArgSourceText is the verbatim source-text representation of each
	// operand at this call site, parallel to Operands. Empty string entries
	// are allowed for operands whose source text is unavailable. Populated
	// by the AST frontend; consumed by rule_engine.go's arg_text_* matchers.
	// Optional — older modules may have empty slices.
	ArgSourceText []string `json:"arg_source_text,omitempty"`
}

// OperandKind distinguishes value references from constant literals.
type OperandKind string

const (
	OperandValue       OperandKind = "value"        // reference to a previously-defined SSA ValueID
	OperandConstString OperandKind = "const_string" // inline string literal
	OperandConstInt    OperandKind = "const_int"    // inline integer literal
	OperandConstBool   OperandKind = "const_bool"
	OperandConstNull   OperandKind = "const_null"
)

// Operand is a single instruction input. Inline constants are stored directly
// rather than as separate OpConst instructions — this keeps the IR compact
// and makes AST-local rule matching (e.g. "first argument is the string
// literal 'DES'") straightforward.
type Operand struct {
	Kind    OperandKind `json:"kind"`
	Value   ValueID     `json:"value,omitempty"`    // for OperandValue
	StrVal  string      `json:"str_val,omitempty"`  // for OperandConstString
	IntVal  int64       `json:"int_val,omitempty"`  // for OperandConstInt
	BoolVal bool        `json:"bool_val,omitempty"` // for OperandConstBool
}

// Location is a source-code location attached to every instruction. Line and
// Column are 1-indexed; EndLine is optional and reported when the frontend
// can supply a span. File is a hint — the authoritative file is always the
// owning Module.Path.
type Location struct {
	File    string `json:"file,omitempty"`
	Line    int    `json:"line"`
	Column  int    `json:"column,omitempty"`
	EndLine int    `json:"end_line,omitempty"`
}
