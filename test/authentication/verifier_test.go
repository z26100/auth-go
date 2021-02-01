package jwt

import (
	"github.com/dgrijalva/jwt-go"
	auth "github.com/z26100/auth-go"
	"net/http"
	"testing"
)

var (
	to = `eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJPMmk3VGY5Tlg5a3FNaVpLc0dPUzlFWWEyY1NwRS1IeFlfcGJuejhhVGdzIn0.eyJqdGkiOiIyYzkxYjA1My1jODY3LTRkZWMtOWVlYy1iMzk5MmE5Zjc1MjgiLCJleHAiOjE2MTIxMDE1MjQsIm5iZiI6MCwiaWF0IjoxNjEyMTAxMjI0LCJpc3MiOiJodHRwczovL2tleWNsb2FrLmFsdGVtaXN0YS5jbG91ZC9hdXRoL3JlYWxtcy9OR0UiLCJhdWQiOlsibmF0ZSIsImFjY291bnQiXSwic3ViIjoiYTNiMDE5OGEtY2JlOS00Mjc1LThjYTEtYzM2MDIzMDRjMjY0IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGVjaHJhZGFyIiwibm9uY2UiOiJiMjkyODc0NS0yYzY3LTQyYmEtOGNlOS1mMGM2ZGJmNDU2OTEiLCJhdXRoX3RpbWUiOjE2MTIxMDEyMjQsInNlc3Npb25fc3RhdGUiOiJhNzBmYzQzYy02NWZjLTRlOGQtODA0Mi00N2IxNDI4YTc0MGQiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHBzOi8vdGVjaHJhZGFyLmJhbGxwYXJrLmFsdGVtaXN0YS5jbG91ZCJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7Im5hdGUiOnsicm9sZXMiOlsiTkFURV9VU0VSX0RFRkFVTFQiLCJOQVRFX1VTRVJfUU0iLCJOQVRFX1VTRVJfREVWRUxPUEVSIiwiTkFURV9VU0VSX0FETUlOIiwiTkFURV9VU0VSX0VYVEVSTkFMIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiQXJuaGVpdGVyIEFybmhlaXRlciIsInByZWZlcnJlZF91c2VybmFtZSI6ImNocmlzdGlhbi5hcm5oZWl0ZXJAbnR0ZGF0YS5jb20iLCJnaXZlbl9uYW1lIjoiQXJuaGVpdGVyIiwiZmFtaWx5X25hbWUiOiJBcm5oZWl0ZXIiLCJlbWFpbCI6ImNocmlzdGlhbi5hcm5oZWl0ZXJAbnR0ZGF0YS5jb20ifQ.LbmivF5eQ86WCP8GIkx10J7qkQrOwk_-erwtu4FwY09bRINrAD-8rvU-cMhDCLAX5QJP9ypODZS6FvPMSOIl0VW4cxxPckbDlB0Z1TE06NhBD9AzHdNmwxIf4aWCvb6b66supA-unrUAzwUrr1VbQSn5HJTdWEAC1nIab_DfzHTFYPKrCLNcQUOgrUXpH7PiwZFBMc4pypgPUnIxmtwkTjipkSWUdWhcSHSBqW2n8v2135vQ-Tz8GBmT9sQab3Ttd0Wh5bHuAym7lqVZ_v-ufY_aMVm5-79zoB30bzhYdG9Ra_Q-x20JWZ-ZeUkKNdWy7VJXjEk5g22dgwi23X9S5g`
)

func token(t *testing.T) string {
	return to
}

func TestVerifier(t *testing.T) {
	provider := auth.NewFilePublicKeyProvider("sample-pk.pem")
	verifier, err := auth.NewJwtVerifier(provider)
	if err != nil {
		t.Fatal(err)
	}
	if verifier == nil {
		t.Fatal(err)
	}
	claims, err := verifier.Validate(token(t))
	if err == nil {
		t.Fatal(err)
	}
	if err.Error() != "Token is expired" {
		t.Fatal(err)
	}
	if claims == nil {
		t.Fatal(err)
	}
}

func TestHttpHandler_expiredToken(t *testing.T) {
	provider := auth.NewFilePublicKeyProvider("sample-pk.pem")
	verifier, err := auth.NewJwtVerifier(provider)
	if err != nil {
		t.Fatal(err)
	}
	if verifier == nil {
		t.Fatal(err)
	}

	claimHandler := func(claims jwt.MapClaims, r *http.Request, w http.ResponseWriter) error {
		t.Fatal("claim handling should not been invoked due to authentication err")
		return nil
	}
	m := newMockHttpHandler(func(request http.Request) {
		t.Fatal("we did not expect to run this code line")
	})
	errorHandler := func(w http.ResponseWriter, err error) error {
		if err == nil || err.Error() != "Token is expired" {
			t.Fatal("We expected an authentication error")
		}
		return err
	}
	handler := auth.HttpTokenHandler(verifier, claimHandler, errorHandler, m)
	r, err := http.NewRequest("GET", "https://example.com/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token(t))
	handler.ServeHTTP(newMockWriter(func(status int) {
	}, func(data []byte) {
	}), r)
}

func TestHttpHandler_claimHandling(t *testing.T) {
	provider := auth.NewFilePublicKeyProvider("sample-pk.pem")
	verifier, err := auth.NewJwtVerifier(provider)
	if err != nil {
		t.Fatal(err)
	}
	if verifier == nil {
		t.Fatal(err)
	}

	auth.NewRBAC()
	defer auth.CloseRBAC()
	err = auth.LoadFromFile("test.yaml")
	if err != nil {
		t.Fatal(err)
	}

	claimHandler := auth.SetUserInHeaderHandler()
	m := newMockHttpHandler(func(request http.Request) {
		if request.Header.Get("userId") != "christian.arnheiter@nttdata.com" {
			t.Fatal("header has not been set correctly")
		}
	})
	errorHandler := func(w http.ResponseWriter, err error) error {
		return nil // ignore authentication errors
	}
	handler := auth.HttpTokenHandler(verifier, claimHandler, errorHandler, m)
	r, err := http.NewRequest("GET", "https://example.com/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token(t))
	handler.ServeHTTP(newMockWriter(func(status int) {
	}, func(data []byte) {
	}), r)
}
