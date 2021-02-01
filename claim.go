package auth

import (
	"github.com/dgrijalva/jwt-go"
	"net/http"
)

type ClaimHandler func(jwt.MapClaims, *http.Request, http.ResponseWriter) error

func SetUserInHeaderHandler() ClaimHandler {
	return func(claims jwt.MapClaims, r *http.Request, w http.ResponseWriter) error {
		r.Header.Set("userId", claims["email"].(string))
		return nil
	}
}
