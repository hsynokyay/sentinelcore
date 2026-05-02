package ir

import (
	"encoding/json"
	"testing"
)

func TestBuildAndRoundtrip(t *testing.T) {
	mod := NewModule("src/main/java/com/example/Foo.java", "java").
		Package("com.example").
		Import("javax.crypto.Cipher").
		Class("Foo", "com.example.Foo").
		Method("bad", Unknown()).
		EntryBlock().
		Call(
			"javax.crypto.Cipher",
			"getInstance",
			"javax.crypto.Cipher.getInstance",
			Nominal("javax.crypto.Cipher"),
			At(10, 5),
			ConstString("DES"),
		)
	_ = mod

	built := mod.Done().Done().Build()

	if built.Language != "java" {
		t.Fatalf("language: got %q", built.Language)
	}
	if len(built.Classes) != 1 {
		t.Fatalf("classes: got %d, want 1", len(built.Classes))
	}
	if built.Classes[0].FQN != "com.example.Foo" {
		t.Fatalf("class fqn: got %q", built.Classes[0].FQN)
	}
	if len(built.Classes[0].Methods) != 1 {
		t.Fatalf("methods: got %d, want 1", len(built.Classes[0].Methods))
	}
	fn := built.Classes[0].Methods[0]
	if fn.Name != "bad" {
		t.Fatalf("method name: got %q", fn.Name)
	}
	if len(fn.Blocks) != 1 || len(fn.Blocks[0].Instructions) != 1 {
		t.Fatalf("expected 1 block with 1 instruction, got %+v", fn.Blocks)
	}
	call := fn.Blocks[0].Instructions[0]
	if call.Op != OpCall {
		t.Fatalf("opcode: got %s", call.Op)
	}
	if call.ReceiverType != "javax.crypto.Cipher" || call.Callee != "getInstance" {
		t.Fatalf("call target: %+v", call)
	}
	if len(call.Operands) != 1 || call.Operands[0].Kind != OperandConstString || call.Operands[0].StrVal != "DES" {
		t.Fatalf("operands: %+v", call.Operands)
	}

	// Round-trip through JSON.
	b, err := json.Marshal(built)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded Module
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.ID != built.ID || decoded.Classes[0].FQN != built.Classes[0].FQN {
		t.Fatalf("roundtrip mismatch")
	}
	if decoded.Classes[0].Methods[0].Blocks[0].Instructions[0].Callee != "getInstance" {
		t.Fatalf("roundtrip lost call info")
	}
}

func TestTypeEqual(t *testing.T) {
	cases := []struct {
		a, b Type
		want bool
	}{
		{Primitive("int"), Primitive("int"), true},
		{Primitive("int"), Primitive("long"), false},
		{Nominal("java.lang.String"), Nominal("java.lang.String"), true},
		{Nominal("java.lang.String"), Primitive("int"), false},
		{Array(Primitive("byte")), Array(Primitive("byte")), true},
		{Array(Primitive("byte")), Array(Primitive("int")), false},
		{Unknown(), Unknown(), true},
	}
	for _, tc := range cases {
		if got := tc.a.Equal(tc.b); got != tc.want {
			t.Errorf("%+v.Equal(%+v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestModuleIDDeterministic(t *testing.T) {
	m1 := NewModule("src/Foo.java", "java").Build()
	m2 := NewModule("src/Foo.java", "java").Build()
	m3 := NewModule("src/Bar.java", "java").Build()
	if m1.ID != m2.ID {
		t.Errorf("same path should produce same ID")
	}
	if m1.ID == m3.ID {
		t.Errorf("different paths should produce different IDs")
	}
}
