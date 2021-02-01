package auth

import (
	"fmt"
)

const (
	header  = "-----BEGIN PUBLIC KEY-----"
	trailer = "-----END PUBLIC KEY-----"
)

func getPublicKeyAsPEM(publicKey string) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%s\n", header, publicKey, trailer))
}
