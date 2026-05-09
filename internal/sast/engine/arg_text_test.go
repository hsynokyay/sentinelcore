package engine

import (
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
	"github.com/sentinelcore/sentinelcore/internal/sast/rules"
)

func TestArgTextContainsAny(t *testing.T) {
	one := 1
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
		Operands: []ir.Operand{
			{Kind: ir.OperandConstString, StrVal: "session"},
			{Kind: ir.OperandValue, Value: 7},
		},
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
	one := 1
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
		Operands: []ir.Operand{
			{Kind: ir.OperandConstString, StrVal: "session"},
			{Kind: ir.OperandValue, Value: 7},
		},
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
		Op:            ir.OpCall,
		ReceiverType:  "res",
		Callee:        "cookie",
		Operands:      []ir.Operand{{Kind: ir.OperandConstString, StrVal: "session"}},
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
		Op:            ir.OpCall,
		ReceiverType:  "res",
		Callee:        "cookie",
		Operands:      []ir.Operand{{Kind: ir.OperandConstString, StrVal: "session"}},
		ArgSourceText: []string{`"session"`},
	}
	if callMatchesPattern(inst, pattern) {
		t.Fatalf("expected no match when ArgIndex is out of range")
	}
}

func TestFuncTextContainsAny(t *testing.T) {
	pattern := rules.CompiledPattern{
		Source: rules.CallPattern{
			ReceiverFQN:         "javax.servlet.http.HttpServletResponse",
			Callee:              "addCookie",
			FuncTextContainsAny: []string{"setSecure(false)"},
		},
	}
	inst := &ir.Instruction{
		Op:                    ir.OpCall,
		ReceiverType:          "javax.servlet.http.HttpServletResponse",
		Callee:                "addCookie",
		EnclosingFunctionText: "Cookie c = new Cookie(\"x\",\"y\"); c.setSecure(false); resp.addCookie(c);",
	}
	if !callMatchesPattern(inst, pattern) {
		t.Fatalf("expected match: function text contains 'setSecure(false)'")
	}

	inst.EnclosingFunctionText = "Cookie c = new Cookie(\"x\",\"y\"); c.setSecure(true); resp.addCookie(c);"
	if callMatchesPattern(inst, pattern) {
		t.Fatalf("expected no match when needle is absent")
	}
}

func TestFuncTextMissingAny(t *testing.T) {
	pattern := rules.CompiledPattern{
		Source: rules.CallPattern{
			ReceiverFQN:        "javax.servlet.http.HttpServletResponse",
			Callee:             "addCookie",
			FuncTextMissingAny: []string{"setSecure(true)", ".secure(true)"},
		},
	}
	inst := &ir.Instruction{
		Op:                    ir.OpCall,
		ReceiverType:          "javax.servlet.http.HttpServletResponse",
		Callee:                "addCookie",
		EnclosingFunctionText: "Cookie c = new Cookie(\"x\",\"y\"); resp.addCookie(c);",
	}
	if !callMatchesPattern(inst, pattern) {
		t.Fatalf("expected match: function text missing all setSecure spellings")
	}

	inst.EnclosingFunctionText = "Cookie c = new Cookie(\"x\",\"y\"); c.setSecure(true); resp.addCookie(c);"
	if callMatchesPattern(inst, pattern) {
		t.Fatalf("expected no match when at least one form is present")
	}
}

func TestFuncText_EmptyEnclosing_FailsClosed(t *testing.T) {
	pattern := rules.CompiledPattern{
		Source: rules.CallPattern{
			ReceiverFQN:        "javax.servlet.http.HttpServletResponse",
			Callee:             "addCookie",
			FuncTextMissingAny: []string{"setSecure(true)"},
		},
	}
	inst := &ir.Instruction{
		Op:           ir.OpCall,
		ReceiverType: "javax.servlet.http.HttpServletResponse",
		Callee:       "addCookie",
		// EnclosingFunctionText empty
	}
	if callMatchesPattern(inst, pattern) {
		t.Fatalf("expected no match when EnclosingFunctionText is empty")
	}
}
