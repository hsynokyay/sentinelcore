package auth

import (
	"fmt"
	"unicode"
)

// PasswordMinLength is the minimum password length for enterprise compliance.
const PasswordMinLength = 12

// ValidatePasswordComplexity checks that a password meets enterprise complexity requirements:
// minimum 12 characters, at least 1 uppercase, 1 lowercase, 1 digit, 1 special character.
// Returns nil if valid, or an error describing the first unmet requirement.
func ValidatePasswordComplexity(password string) error {
	if len(password) < PasswordMinLength {
		return fmt.Errorf("password must be at least %d characters", PasswordMinLength)
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return fmt.Errorf("password must contain at least one digit")
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}
