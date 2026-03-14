package auth

import (
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	password := "my-secret-password-123!"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("hash should not be empty")
	}
	if hash == password {
		t.Fatal("hash should not equal plaintext password")
	}

	if !VerifyPassword(hash, password) {
		t.Error("correct password should verify")
	}
}

func TestVerifyPassword_Wrong(t *testing.T) {
	hash, err := HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if VerifyPassword(hash, "wrong-password") {
		t.Error("wrong password should not verify")
	}
}

func TestHashPassword_Unique(t *testing.T) {
	hash1, _ := HashPassword("same-password")
	hash2, _ := HashPassword("same-password")
	if hash1 == hash2 {
		t.Error("two hashes of the same password should differ (different salts)")
	}
}
