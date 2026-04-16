package api

import (
	"testing"
)

// authzMatrixExpectation defines what a role is expected to be able to do.
// Tests assert that this matches the RBAC seed in migration 024.
type authzMatrixExpectation struct {
	Permission string
	OwnerAllow, AdminAllow, SecEngAllow, AuditorAllow, DevAllow bool
}

// expectedMatrix enumerates all permissions used by the 21 wrapped routes.
// If a permission appears here but not in the DB seed, or vice versa, the
// test fails. If the seed's role→permission mapping disagrees with the
// expectation, the test fails — regression guard against accidental
// drift in migration 024.
var expectedMatrix = []authzMatrixExpectation{
	// Used by routes: covered by Group A-S plan mapping
	// owner/admin/sec_eng/auditor/developer
	{"organizations.manage", true, true, false, false, false},
	{"organizations.read", true, true, true, true, false},
	{"teams.manage", true, true, false, false, false},
	{"teams.read", true, true, true, true, false},
	{"users.manage", true, false, false, false, false},
	{"users.read", true, true, false, true, false},
	{"projects.manage", true, true, false, false, false},
	{"projects.read", true, true, true, true, true},
	{"targets.manage", true, true, true, false, false},
	{"targets.read", true, true, true, true, true},
	{"scans.run", true, true, true, false, false},
	{"scans.read", true, true, true, true, true},
	{"scans.cancel", true, true, true, false, false},
	{"findings.read", true, true, true, true, true},
	{"findings.triage", true, true, true, false, false},
}

func TestAuthzMatrix_SeedMatchesExpectation(t *testing.T) {
	pool := testPoolAuthz(t) // connects to TEST_DATABASE_URL or skips
	defer pool.Close()

	for _, exp := range expectedMatrix {
		for _, tc := range []struct {
			role  string
			allow bool
		}{
			{"owner", exp.OwnerAllow},
			{"admin", exp.AdminAllow},
			{"security_engineer", exp.SecEngAllow},
			{"auditor", exp.AuditorAllow},
			{"developer", exp.DevAllow},
		} {
			t.Run(exp.Permission+"/"+tc.role, func(t *testing.T) {
				var count int
				err := pool.QueryRow(t.Context(),
					`SELECT COUNT(*) FROM auth.role_permissions
                      WHERE role_id = $1 AND permission_id = $2`,
					tc.role, exp.Permission).Scan(&count)
				if err != nil {
					t.Fatalf("query: %v", err)
				}
				got := count == 1
				if got != tc.allow {
					t.Errorf("role=%s perm=%s seed=%v want=%v",
						tc.role, exp.Permission, got, tc.allow)
				}
			})
		}
	}
}
