// Package fixtures builds SentinelIR modules from hand-written Java code
// shapes. It is the Chunk SAST-1 stand-in for a real Java frontend: it
// exists so the IR, rule engine, fingerprint, and evidence chain can be
// exercised end-to-end before the JVM-based JavaParser sidecar lands in
// Chunk SAST-2.
//
// Every fixture here corresponds to a tiny .java source file that we would
// expect a real frontend to produce equivalent IR for. Each fixture is
// documented with the Java source it represents so the equivalence is
// reviewable.
//
// Once Chunk SAST-2 lands the real frontend, these fixtures become
// regression tests (the IR shapes the frontend must produce for the same
// source code) rather than the engine's only input.
package fixtures

import (
	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
)

// WeakCryptoDES returns a module equivalent to:
//
//	package com.example;
//	import javax.crypto.Cipher;
//	public class WeakCryptoDES {
//	    public void bad() throws Exception {
//	        Cipher c = Cipher.getInstance("DES");   // line 6
//	    }
//	}
//
// This fixture exercises the SC-JAVA-CRYPTO-001 rule's first pattern
// (Cipher.getInstance with a weak algorithm literal). It must produce
// exactly one finding.
func WeakCryptoDES() *ir.Module {
	return ir.NewModule("src/main/java/com/example/WeakCryptoDES.java", "java").
		Package("com.example").
		Import("javax.crypto.Cipher").
		Class("WeakCryptoDES", "com.example.WeakCryptoDES").
		Method("bad", ir.Unknown()).
		EntryBlock().
		Call(
			"javax.crypto.Cipher",
			"getInstance",
			"javax.crypto.Cipher.getInstance",
			ir.Nominal("javax.crypto.Cipher"),
			ir.At(6, 20),
			ir.ConstString("DES"),
		).
		Return(ir.At(7, 5)).
		Done().
		Done().
		Build()
}

// StrongCryptoAES returns a module equivalent to:
//
//	package com.example;
//	import javax.crypto.Cipher;
//	public class StrongCryptoAES {
//	    public void good() throws Exception {
//	        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
//	    }
//	}
//
// This is the negative fixture for SC-JAVA-CRYPTO-001 — it must produce
// zero findings.
func StrongCryptoAES() *ir.Module {
	return ir.NewModule("src/main/java/com/example/StrongCryptoAES.java", "java").
		Package("com.example").
		Import("javax.crypto.Cipher").
		Class("StrongCryptoAES", "com.example.StrongCryptoAES").
		Method("good", ir.Unknown()).
		EntryBlock().
		Call(
			"javax.crypto.Cipher",
			"getInstance",
			"javax.crypto.Cipher.getInstance",
			ir.Nominal("javax.crypto.Cipher"),
			ir.At(6, 20),
			ir.ConstString("AES/GCM/NoPadding"),
		).
		Return(ir.At(7, 5)).
		Done().
		Done().
		Build()
}

// WeakHashMD5 returns a module equivalent to:
//
//	package com.example;
//	import java.security.MessageDigest;
//	public class WeakHashMD5 {
//	    public void hash() throws Exception {
//	        MessageDigest md = MessageDigest.getInstance("MD5");
//	    }
//	}
//
// Exercises SC-JAVA-CRYPTO-001's second pattern (MessageDigest.getInstance
// with a broken hash literal).
func WeakHashMD5() *ir.Module {
	return ir.NewModule("src/main/java/com/example/WeakHashMD5.java", "java").
		Package("com.example").
		Import("java.security.MessageDigest").
		Class("WeakHashMD5", "com.example.WeakHashMD5").
		Method("hash", ir.Unknown()).
		EntryBlock().
		Call(
			"java.security.MessageDigest",
			"getInstance",
			"java.security.MessageDigest.getInstance",
			ir.Nominal("java.security.MessageDigest"),
			ir.At(6, 30),
			ir.ConstString("MD5"),
		).
		Return(ir.At(7, 5)).
		Done().
		Done().
		Build()
}

// MixedCryptoBatch returns a module that contains three calls:
//
//	Cipher.getInstance("DES")               // should fire
//	MessageDigest.getInstance("SHA-256")    // should NOT fire (strong hash)
//	Cipher.getInstance("AES/CBC/PKCS5Padding") // should NOT fire (AES)
//
// This fixture tests that the rule engine correctly filters matches at
// module scope — one finding should come out of three calls.
func MixedCryptoBatch() *ir.Module {
	fn := ir.NewModule("src/main/java/com/example/Mixed.java", "java").
		Package("com.example").
		Import("javax.crypto.Cipher", "java.security.MessageDigest").
		Class("Mixed", "com.example.Mixed").
		Method("mix", ir.Unknown()).
		EntryBlock()

	fn.Call("javax.crypto.Cipher", "getInstance", "javax.crypto.Cipher.getInstance",
		ir.Nominal("javax.crypto.Cipher"), ir.At(7, 20), ir.ConstString("DES"))
	fn.Call("java.security.MessageDigest", "getInstance", "java.security.MessageDigest.getInstance",
		ir.Nominal("java.security.MessageDigest"), ir.At(8, 30), ir.ConstString("SHA-256"))
	fn.Call("javax.crypto.Cipher", "getInstance", "javax.crypto.Cipher.getInstance",
		ir.Nominal("javax.crypto.Cipher"), ir.At(9, 20), ir.ConstString("AES/CBC/PKCS5Padding"))
	fn.Return(ir.At(10, 5))

	return fn.Done().Done().Build()
}

// ECBModeViolation returns a module equivalent to:
//
//	Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
//
// ECB is broken even when combined with a strong cipher like AES; the rule
// must catch this via the "(/|^)ECB(/|$)" pattern.
func ECBModeViolation() *ir.Module {
	return ir.NewModule("src/main/java/com/example/ECB.java", "java").
		Package("com.example").
		Import("javax.crypto.Cipher").
		Class("ECB", "com.example.ECB").
		Method("encrypt", ir.Unknown()).
		EntryBlock().
		Call(
			"javax.crypto.Cipher",
			"getInstance",
			"javax.crypto.Cipher.getInstance",
			ir.Nominal("javax.crypto.Cipher"),
			ir.At(6, 20),
			ir.ConstString("AES/ECB/PKCS5Padding"),
		).
		Return(ir.At(7, 5)).
		Done().
		Done().
		Build()
}

// NonLiteralCipherArg returns a module where the argument to
// Cipher.getInstance is a value reference (e.g. a parameter), not a string
// literal. The AST-local matcher in Chunk SAST-1 must NOT fire — the taint
// engine in Chunk SAST-3 is the one that can reach back to the definition
// site. This fixture documents that limitation explicitly.
func NonLiteralCipherArg() *ir.Module {
	return ir.NewModule("src/main/java/com/example/NonLit.java", "java").
		Package("com.example").
		Import("javax.crypto.Cipher").
		Class("NonLit", "com.example.NonLit").
		Method("fromParam", ir.Unknown(), ir.Parameter{
			Name: "algo",
			Type: ir.Nominal("java.lang.String"),
			Value: ir.ValueID(1),
		}).
		EntryBlock().
		Call(
			"javax.crypto.Cipher",
			"getInstance",
			"javax.crypto.Cipher.getInstance",
			ir.Nominal("javax.crypto.Cipher"),
			ir.At(6, 20),
			ir.ValueRef(ir.ValueID(1)),
		).
		Return(ir.At(7, 5)).
		Done().
		Done().
		Build()
}
