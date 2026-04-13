package engine

import "testing"

func TestFingerprintStable(t *testing.T) {
	a := Fingerprint("SC-JAVA-CRYPTO-001", "src/Foo.java", "com.example.Foo.bad", "javax.crypto.Cipher.getInstance", "DES")
	b := Fingerprint("SC-JAVA-CRYPTO-001", "src/Foo.java", "com.example.Foo.bad", "javax.crypto.Cipher.getInstance", "DES")
	if a != b {
		t.Errorf("same inputs → different fingerprints: %s vs %s", a, b)
	}
	if len(a) != 64 {
		t.Errorf("fingerprint length: got %d, want 64", len(a))
	}
}

func TestFingerprintDifferentForDifferentInputs(t *testing.T) {
	cases := []struct {
		name string
		a, b string
	}{
		{"different rule_id",
			Fingerprint("SC-JAVA-CRYPTO-001", "p", "f", "c", "a"),
			Fingerprint("SC-JAVA-CRYPTO-002", "p", "f", "c", "a")},
		{"different module",
			Fingerprint("r", "p1", "f", "c", "a"),
			Fingerprint("r", "p2", "f", "c", "a")},
		{"different function",
			Fingerprint("r", "p", "f1", "c", "a"),
			Fingerprint("r", "p", "f2", "c", "a")},
		{"different callee",
			Fingerprint("r", "p", "f", "c1", "a"),
			Fingerprint("r", "p", "f", "c2", "a")},
		{"different arg",
			Fingerprint("r", "p", "f", "c", "DES"),
			Fingerprint("r", "p", "f", "c", "RC4")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.a == tc.b {
				t.Errorf("%s: expected different, both = %s", tc.name, tc.a)
			}
		})
	}
}
