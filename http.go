package auth

import (
	"errors"
	"fmt"
	log "github.com/z26100/log-go"
	"net/http"
	"strings"
)

type ErrorHandler func(http.ResponseWriter, error) error

func HttpTokenHandler(verifier *JwtVerifier, claimHandler ClaimHandler, errorHandler ErrorHandler, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// no JWT verifier, so just pass it to the next handler without any verification
		if verifier == nil {
			h.ServeHTTP(w, r)
			return
		}
		bearerToken, err := GetBearerToken(*r)
		if err != nil {
			r.Header.Set("userId", "anonymous")
		}
		// JWT verification means authentication
		claims, err := verifier.Validate(bearerToken)
		// pass the result to the error handler
		if errorHandler(w, err) != nil {
			return
		}
		// pass the claims to the claim handler
		if claimHandler != nil {
			err = claimHandler(claims, r, w)
			if err != nil {
				return
			}
		}
		// if error handler and claim handler returned no error we can
		// safely pass the request to the next handler
		h.ServeHTTP(w, r)
	})
}

func GetBearerToken(r http.Request) (string, error) {
	reqToken := r.Header.Get("Authorization")
	splitToken := strings.Split(reqToken, "Bearer ")
	if len(splitToken) != 2 {
		return "", errors.New("no bearer token found")
	}
	log.Debugf("Bearer Token =  %s", splitToken[1])
	return strings.TrimSpace(splitToken[1]), nil
}

func ThrowUnauthorizedException(r http.Request, w http.ResponseWriter) error {
	err := errors.New(fmt.Sprintf("Unauthorized request %s %s", r.Method, r.RequestURI))
	http.Error(w, err.Error(), http.StatusUnauthorized)
	return err
}
