package auth

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

type JwtVerifier struct {
	provider PublicKeyProvider
}

func NewJwtVerifier(provider PublicKeyProvider) (*JwtVerifier, error) {
	result := &JwtVerifier{
		provider: provider,
	}
	return result, nil
}

// Parse takes the token string and a function for looking up the key. The latter is especially
// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
// head of the token to identify which key to use, but the parsed token (head and claims) is provided
// to the callback, providing flexibility.
func (v JwtVerifier) Validate(tokenString string) (jwt.MapClaims, error) {
	publicKey, err := v.provider.Get()
	if err != nil {
		return nil, err
	}
	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, err
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodRSA)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return verifyKey, nil
	})
	if token == nil {
		return nil, errors.New("token must not be nil")
	}

	claims := token.Claims.(jwt.MapClaims)
	return claims, err
}
