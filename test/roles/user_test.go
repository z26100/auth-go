package roles

import (
	auth "github.com/z26100/auth-go"
	"testing"
)

func TestStandardUserMgmt(t *testing.T) {
	mgmt := auth.DefaultUserManagement()
	err := mgmt.AddUser("test", auth.Admin)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := mgmt.GetUser("test")
	if err != nil {
		t.Fatal(err)
	}
	if profile == nil {
		t.Fatal("profile must not be nil")
	}
	if !profile.HasRole(auth.Admin) {
		t.Fatal("user must have admin role")
	}
	if profile.HasRole(auth.Viewer) {
		t.Fatal("user must not have viewe role")
	}
	err = mgmt.RemoveRolesFromUser("test", auth.Admin)
	if err != nil {
		t.Fatal(err)
	}
	if profile.HasRole(auth.Admin) {
		t.Fatal("user must not have admin role")
	}
	mgmt.RemoveUser("test")
	profile, err = mgmt.GetUser("test")
	if err == nil || err.Error() != "no user found" {
		t.Fatal("no user found exception expected")
	}
	if profile != nil {
		t.Fatal("profile must be nil")
	}
}

func TestUserMgmtPersistency(t *testing.T) {
	authorization := auth.NewFileBasedRoleAuthorization()
	err := authorization.AddUser("test", auth.Admin)
	if err != nil {
		t.Fatal(err)
	}
	err = authorization.GetUserManagement().AssignRolesToUser("test", auth.Editor)
	if err != nil {
		t.Fatal(err)
	}
	if !authorization.GetUserManagement().HasRole("test", auth.Admin) {
		t.Fatal("no anonymous role found")
	}
	if !authorization.GetUserManagement().HasRole("test", auth.Editor) {
		t.Fatal("no editor role found")
	}
	err = authorization.SaveToFile("test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	authorization.Clear()
	if authorization.GetUserManagement().HasRole("test", auth.Admin) {
		t.Fatal("admin role found")
	}
	if authorization.GetUserManagement().HasRole("test", auth.Editor) {
		t.Fatal("editor role found")
	}
	err = authorization.LoadFromFile("test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !authorization.GetUserManagement().HasRole("test", auth.Admin) {
		t.Fatal("no admin role found")
	}
	if !authorization.GetUserManagement().HasRole("test", auth.Editor) {
		t.Fatal("no editor role found")
	}
}
