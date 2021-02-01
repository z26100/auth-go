package jwt

import (
	auth "github.com/z26100/auth-go"
	"log"
	"net/http"
	"testing"
)

func TestRBACGetPublicResourceWithoutAuthentication(t *testing.T) {
	provider := auth.NewFilePublicKeyProvider("sample-pk.pem")
	verifier, err := auth.NewJwtVerifier(provider)
	if err != nil {
		t.Fatal(err)
	}
	if verifier == nil {
		t.Fatal(err)
	}
	claimHandler := auth.DefaultRBACBasedClaimHandler(auth.NewSimpleRoleAuthorization())
	m := newMockHttpHandler(func(request http.Request) {})
	errorHandler := func(w http.ResponseWriter, err error) error { return nil }
	handler := auth.HttpTokenHandler(verifier, claimHandler, errorHandler, m)
	strip := http.StripPrefix("/api/v2", handler)
	// public endpoints can be viewed by everybody
	r, err := http.NewRequest("GET", "https://example.com/api/v2/public", nil)
	if err != nil {
		t.Fatal(err)
	}
	strip.ServeHTTP(newMockWriter(func(status int) {
		log.Println(status)
		if status != 200 {
			t.Fatalf("return code %d unexpected", status)
		}
	}, func(data []byte) {}), r)
}

func TestRBACGetResource(t *testing.T) {

	auth.NewRBAC()
	defer auth.CloseRBAC()
	role, err := auth.NewRole("viewer")
	if err != nil {
		t.Fatal(err)
	}
	permission := auth.AddPermission("get::data:tags")
	err = role.Assign(permission)
	if err != nil {
		t.Fatal(err)
	}
	provider := auth.NewFilePublicKeyProvider("sample-pk.pem")
	verifier, err := auth.NewJwtVerifier(provider)
	if err != nil {
		t.Fatal(err)
	}
	if verifier == nil {
		t.Fatal(err)
	}
	authorization := auth.NewSimpleRoleAuthorization()
	claimHandler := auth.DefaultRBACBasedClaimHandler(authorization)
	m := newMockHttpHandler(func(request http.Request) {})
	errorHandler := func(w http.ResponseWriter, err error) error { return nil }
	handler := auth.HttpTokenHandler(verifier, claimHandler, errorHandler, m)
	strip := http.StripPrefix("/api/v2", handler)
	// public endpoints can be viewed by everybody
	r, err := http.NewRequest("GET", "https://example.com/api/v2/data/tags", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token(t))
	err = authorization.GetUserManagement().AddUser("christian.arnheiter@nttdata.com", auth.Viewer)
	if err != nil {
		t.Fatal(err)
	}
	strip.ServeHTTP(newMockWriter(func(status int) {
		if status != 200 {
			t.Fatalf("return code %d unexpected", status)
		}
	}, func(data []byte) {}), r)
	err = authorization.GetUserManagement().RemoveRolesFromUser("christian.arnheiter@nttdata.com", auth.Viewer)
	if err != nil {
		t.Fatal(err)
	}
	strip.ServeHTTP(newMockWriter(func(status int) {
		if status != 401 {
			t.Fatalf("return code %d unexpected", status)
		}
	}, func(data []byte) {}), r)
}

func TestRBACGetAdminResource(t *testing.T) {
	provider := auth.NewFilePublicKeyProvider("sample-pk.pem")
	verifier, err := auth.NewJwtVerifier(provider)
	if err != nil {
		t.Fatal(err)
	}
	if verifier == nil {
		t.Fatal(err)
	}
	authorization := auth.NewSimpleRoleAuthorization()
	claimHandler := auth.DefaultRoleBasedClaimHandler(authorization)
	m := newMockHttpHandler(func(request http.Request) {})
	errorHandler := func(w http.ResponseWriter, err error) error { return nil }
	handler := auth.HttpTokenHandler(verifier, claimHandler, errorHandler, m)
	strip := http.StripPrefix("/api/v2", handler)
	// public endpoints can be viewed by everybody
	r, err := http.NewRequest("GET", "https://example.com/api/v2/_admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token(t))
	strip.ServeHTTP(newMockWriter(func(status int) {
		if status != 401 {
			t.Fatalf("return code %d unexpected", status)
		}
	}, func(data []byte) {}), r)
	err = authorization.GetUserManagement().AddUser("christian.arnheiter@nttdata.com", auth.Viewer)
	if err != nil {
		t.Fatal(err)
	}
	strip.ServeHTTP(newMockWriter(func(status int) {
		if status != 401 {
			t.Fatalf("return code %d unexpected", status)
		}
	}, func(data []byte) {}), r)
	err = authorization.GetUserManagement().AssignRolesToUser("christian.arnheiter@nttdata.com", auth.Admin)
	if err != nil {
		t.Fatal(err)
	}
	strip.ServeHTTP(newMockWriter(func(status int) {
		if status != 200 {
			t.Fatalf("return code %d unexpected", status)
		}
	}, func(data []byte) {}), r)
}

func TestRBACPostResource(t *testing.T) {
	provider := auth.NewFilePublicKeyProvider("sample-pk.pem")
	verifier, err := auth.NewJwtVerifier(provider)
	if err != nil {
		t.Fatal(err)
	}
	if verifier == nil {
		t.Fatal(err)
	}
	authorization := auth.NewSimpleRoleAuthorization()
	claimHandler := auth.DefaultRoleBasedClaimHandler(authorization)
	m := newMockHttpHandler(func(request http.Request) {})
	errorHandler := func(w http.ResponseWriter, err error) error { return nil }
	handler := auth.HttpTokenHandler(verifier, claimHandler, errorHandler, m)
	strip := http.StripPrefix("/api/v2", handler)
	// public endpoints can be viewed by everybody
	r, err := http.NewRequest("POST", "https://example.com/api/v2/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token(t))
	strip.ServeHTTP(newMockWriter(func(status int) {
		if status != 401 {
			t.Fatalf("return code %d unexpected", status)
		}
	}, func(data []byte) {}), r)
	err = authorization.GetUserManagement().AddUser("christian.arnheiter@nttdata.com", auth.Viewer)
	if err != nil {
		t.Fatal(err)
	}
	strip.ServeHTTP(newMockWriter(func(status int) {
		if status != 401 {
			t.Fatalf("return code %d unexpected", status)
		}
	}, func(data []byte) {}), r)
	err = authorization.GetUserManagement().AssignRolesToUser("christian.arnheiter@nttdata.com", auth.Editor)
	if err != nil {
		t.Fatal(err)
	}
	strip.ServeHTTP(newMockWriter(func(status int) {
		if status != 200 {
			t.Fatalf("return code %d unexpected", status)
		}
	}, func(data []byte) {}), r)
	err = authorization.GetUserManagement().RemoveRolesFromUser("christian.arnheiter@nttdata.com", auth.Viewer)
	if err != nil {
		t.Fatal(err)
	}
	strip.ServeHTTP(newMockWriter(func(status int) {
		if status != 401 {
			t.Fatalf("return code %d unexpected", status)
		}
	}, func(data []byte) {}), r)
}
