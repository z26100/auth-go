package auth

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"net/http"
	"strings"
)

type RoleAuthorization interface {
	HasRole(claim jwt.MapClaims, role Role) bool
	GetRoles(claim jwt.MapClaims) []Role
	Clear()
}

type SimpleRoleAuthorization struct {
	*UserManagement
}

func NewSimpleRoleAuthorization() *SimpleRoleAuthorization {
	users := DefaultUserManagement()
	return &SimpleRoleAuthorization{
		&users,
	}
}
func (a SimpleRoleAuthorization) GetUserManagement() *UserManagement {
	return a.UserManagement
}
func (a SimpleRoleAuthorization) getUserId(claims jwt.MapClaims) string {
	userId := claims["email"]
	if userId != nil {
		return userId.(string)
	}
	return ""
}

func (a SimpleRoleAuthorization) HasRole(claims jwt.MapClaims, r Role) bool {
	userId := a.getUserId(claims)
	return a.UserManagement.HasRole(userId, r)
}

func (a SimpleRoleAuthorization) GetRoles(claims jwt.MapClaims) []Role {
	userId := a.getUserId(claims)
	return a.UserManagement.GetRolesForUser(userId)
}

type FileBasedRoleAuthorization struct {
	*SimpleRoleAuthorization
}

type UserRoles struct {
	UserId string   `json:"user" yaml:"user"`
	Roles  []string `json:"Roles" yaml:"Roles"`
}
type UserDictionary struct {
	Users []UserRoles `json:"Roles" yaml:"Roles"`
}

func NewFileBasedRoleAuthorization() *FileBasedRoleAuthorization {
	result := &FileBasedRoleAuthorization{
		SimpleRoleAuthorization: NewSimpleRoleAuthorization(),
	}
	return result
}

func (a *FileBasedRoleAuthorization) Clear() {
	a.UserManagement.Clear()

}
func (a *FileBasedRoleAuthorization) LoadFromFile(filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	if strings.HasSuffix(filename, "json") {
		err = json.Unmarshal(data, &a.Users)
	} else {
		err = yaml.Unmarshal(data, &a.Users)
	}
	return err
}

func (a *FileBasedRoleAuthorization) SaveToFile(filename string) error {
	var err error
	var data []byte
	if strings.HasSuffix(filename, "json") {
		data, err = json.Marshal(a.Users)
	} else {
		data, err = yaml.Marshal(a.Users)
	}
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, data, 0755)
}

func (a *FileBasedRoleAuthorization) getRoles(roles []string) []Role {
	var result []Role
	for _, r := range roles {
		switch r {
		case "admin":
			result = append(result, Admin)
		case "editor":
			result = append(result, Editor)
		case "viewer":
			result = append(result, Viewer)
		}
	}
	return result
}
func (a *FileBasedRoleAuthorization) AddUser(userId string, roles ...Role) error {
	return a.UserManagement.AddUser(userId, roles...)
}

func (a FileBasedRoleAuthorization) getUserId(claims jwt.MapClaims) string {
	userId := claims["email"]
	if userId != nil {
		return userId.(string)
	}
	return ""
}

func (a FileBasedRoleAuthorization) HasRole(claims jwt.MapClaims, r Role) bool {
	userId := a.getUserId(claims)
	return a.UserManagement.HasRole(userId, r)
}

func DefaultRoleBasedClaimHandler(a RoleAuthorization) ClaimHandler {
	return func(claims jwt.MapClaims, r *http.Request, w http.ResponseWriter) error {
		switch r.Method {
		case "GET", "OPTIONS":
			// public endpoints can be viewed
			if strings.HasPrefix(r.URL.Path, "/public") {
				return nil
			}
			//  _admin endpoints can be viewed by admins only
			if strings.HasPrefix(r.URL.Path, "/_admin") && !a.HasRole(claims, Admin) {
				return ThrowUnauthorizedException(*r, w)
			}
			// for all other endpoints we need viewer role
			if a.HasRole(claims, Viewer) {
				return nil
			}
			return ThrowUnauthorizedException(*r, w)
		case "POST", "DELETE", "PUT":
			//  _admin endpoints can be accessed by admins only
			if strings.HasPrefix(r.URL.Path, "/_admin") && !a.HasRole(claims, Admin) {
				return ThrowUnauthorizedException(*r, w)
			}
			// we need editor role for all the other endpoints
			if a.HasRole(claims, Editor) {
				return nil
			}
			return ThrowUnauthorizedException(*r, w)
		default:
			return ThrowUnauthorizedException(*r, w)
		}
	}
}

func DefaultRBACBasedClaimHandler(a RoleAuthorization) ClaimHandler {
	return func(claims jwt.MapClaims, r *http.Request, w http.ResponseWriter) error {
		switch r.Method {
		case "GET", "OPTIONS":
			// public endpoints can be viewed
			if strings.HasPrefix(r.URL.Path, "/public") {
				return nil
			}
			roles := a.GetRoles(claims)
			action := strings.ToLower(fmt.Sprintf("%s:%s", r.Method, strings.ReplaceAll(r.URL.Path, "/", ":")))
			if IsPermitted(roles, action) {
				return nil
			}
			return ThrowUnauthorizedException(*r, w)
		case "POST", "DELETE", "PUT":

			return ThrowUnauthorizedException(*r, w)
		default:
			return ThrowUnauthorizedException(*r, w)
		}
	}
}
