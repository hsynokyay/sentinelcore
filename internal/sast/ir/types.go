package ir

// Kind distinguishes the broad categories of types SentinelIR recognizes.
// The set is deliberately small — the MVP slice only needs enough type
// information to match rule patterns on call receivers, parameter types, and
// return types.
type Kind string

const (
	KindPrimitive Kind = "primitive"
	KindNominal   Kind = "nominal"
	KindArray     Kind = "array"
	KindUnknown   Kind = "unknown"
)

// Type is the minimum shape shared by every language frontend. Later chunks
// will add structural types (TypeScript-style record types) and generics, but
// nominal + primitive + array is enough for Java rule matching in Chunk
// SAST-1.
type Type struct {
	Kind        Kind   `json:"kind"`
	Name        string `json:"name,omitempty"`         // "int", "String", "com.example.Foo"
	ElementType *Type  `json:"element_type,omitempty"` // for arrays
}

// Primitive constructs a primitive type (e.g. "int", "boolean").
func Primitive(name string) Type {
	return Type{Kind: KindPrimitive, Name: name}
}

// Nominal constructs a nominal (class/interface) type from a fully-qualified
// name (e.g. "java.lang.String", "com.example.foo.Bar").
func Nominal(fqn string) Type {
	return Type{Kind: KindNominal, Name: fqn}
}

// Array constructs an array type with the given element type.
func Array(elem Type) Type {
	return Type{Kind: KindArray, ElementType: &elem}
}

// Unknown is the top of the type lattice — used when the frontend cannot
// resolve a type. Rules must treat Unknown conservatively: a value of Unknown
// type that carries taint is still tainted.
func Unknown() Type {
	return Type{Kind: KindUnknown}
}

// Equal returns true if two types are structurally equal.
func (t Type) Equal(other Type) bool {
	if t.Kind != other.Kind || t.Name != other.Name {
		return false
	}
	if t.Kind == KindArray {
		if t.ElementType == nil || other.ElementType == nil {
			return t.ElementType == other.ElementType
		}
		return t.ElementType.Equal(*other.ElementType)
	}
	return true
}
