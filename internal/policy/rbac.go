// Package policy previously held the hardcoded RBAC matrix and the
// Evaluate() function. Both are retired in favour of the DB-driven
// cache (cache.go) + RequirePermission middleware. This file is kept
// as the package home for future policy helpers.
package policy
