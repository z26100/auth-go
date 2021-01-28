package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

const (
	url           = "https://keycloak.altemista.cloud/auth/realms/NGE/protocol/openid-connect/certs"
	header        = "-----BEGIN PUBLIC KEY-----"
	trailer       = "-----END PUBLIC KEY-----"
	certFieldName = "x5c"
)

type Unmarshaler interface {
	Unmarshal(interface{}) (string, error)
}

type JwtVerifier struct {
	publicKey   []byte
	unmarshaler Unmarshaler
}

func NewJwtVerifier() (*JwtVerifier, error) {
	result := &JwtVerifier{
		publicKey:   nil,
		unmarshaler: NewKeycloakUnmarshaler(certFieldName),
	}
	return result, nil
}

func NewVerifierWithPEMFile(filename string) (*JwtVerifier, error) {
	result, err := NewJwtVerifier()
	if result == nil {
		return nil, err
	}
	_, err = result.ReadPublicKeyAsPEMFromFile(filename)
	return result, err
}

func NewVerifierWithCertificateLink(url string) (*JwtVerifier, error) {
	result, err := NewJwtVerifier()
	if result == nil {
		return nil, err
	}
	_, err = result.ReadPublicKeyFromWebsite(url)
	return result, err
}

func (v *JwtVerifier) SetCertFieldName(name string) {
	v.unmarshaler = NewKeycloakUnmarshaler(name)
}

func (v *JwtVerifier) SetUnmarshaler(m Unmarshaler) {
	v.unmarshaler = m
}

type KeycloakUnmarshaler struct {
	fieldName string
}

func NewKeycloakUnmarshaler(fieldName string) *KeycloakUnmarshaler {
	return &KeycloakUnmarshaler{fieldName: fieldName}
}

func (k KeycloakUnmarshaler) Unmarshal(d interface{}) (result string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("array index out of bounds")
		}
	}()
	result = d.(map[string]interface{})["keys"].([]interface{})[0].(map[string]interface{})[k.fieldName].([]interface{})[0].(string)
	return result, err
}

func (v *JwtVerifier) ReadPublicKeyFromWebsite(url string) ([]byte, error) {
	log.Printf("reading public key from %s", url)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var certs interface{}
	err = json.Unmarshal(body, &certs)
	if err != nil {
		return nil, err
	}
	publicKey, err := v.unmarshaler.Unmarshal(certs)
	if err != nil {
		return nil, err
	}
	log.Printf("Public Key=%s", publicKey)
	if publicKey == "" {
		return nil, errors.New("public key not found")
	}
	v.publicKey = v.getPublicKeyAsPEM(publicKey)
	return v.publicKey, nil
}

func (v JwtVerifier) getPublicKeyAsPEM(publicKey string) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%s\n", header, publicKey, trailer))
}

func (v *JwtVerifier) ReadPublicKeyAsPEMFromFile(filename string) ([]byte, error) {
	pem, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	v.publicKey = pem
	return pem, err
}

// Parse takes the token string and a function for looking up the key. The latter is especially
// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
// head of the token to identify which key to use, but the parsed token (head and claims) is provided
// to the callback, providing flexibility.
func (v JwtVerifier) Validate(tokenString string) (jwt.MapClaims, error) {
	if v.publicKey == nil {
		return nil, errors.New("public key must not be nil")
	}
	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(v.publicKey)
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
	if err != nil {
		return nil, err
	}
	claims := token.Claims.(jwt.MapClaims)
	return claims, nil
}
func CheckJwtToken(verifier *JwtVerifier, claimHandler func(claims jwt.MapClaims, r *http.Request, w http.ResponseWriter) error, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// no JWT verifier, so just pass it to the next handler without any verification
		if verifier == nil {
			h.ServeHTTP(w, r)
			return
		}
		bearerToken, err := getBearerToken(*r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		claims, err := verifier.Validate(bearerToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if claimHandler != nil {
			err = claimHandler(claims, r, w)
			if err != nil {
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

func getBearerToken(r http.Request) (string, error) {
	reqToken := r.Header.Get("Authorization")
	splitToken := strings.Split(reqToken, "Bearer ")
	if len(splitToken) != 2 {
		return "", errors.New("no bearer token found")
	}
	log.Printf("Bearer Token =  %s", splitToken[1])
	return strings.TrimSpace(splitToken[1]), nil
}
