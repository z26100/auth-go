package auth

import (
	"errors"
)

type Adapter interface {
	Get(interface{}) (string, error)
}

type KeycloakAdapter struct {
	fieldName string
}

func NewKeycloakAdapter(fieldName string) *KeycloakAdapter {
	return &KeycloakAdapter{fieldName: fieldName}
}

func (k KeycloakAdapter) Get(d interface{}) (result string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("array index out of bounds")
		}
	}()
	result = d.(map[string]interface{})["keys"].([]interface{})[0].(map[string]interface{})[k.fieldName].([]interface{})[0].(string)
	return result, err
}
