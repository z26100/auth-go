package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	flag "github.com/z26100/service-config-go"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

const (
	configFilePath        = "userDictionary"
	defaultConfigFilePath = "config/users.yaml"
)

var (
	configFilePathVar = flag.String(configFilePath, defaultConfigFilePath, "config file path")
)

type Auth struct {
	filename string
	users    UserManagement
}

func NewDefaultAuth() *Auth {
	return NewAuth(*configFilePathVar)
}

func NewAuth(filename string) *Auth {
	result := &Auth{
		users:    DefaultUsermanagement(),
		filename: filename,
	}
	err := result.LoadUsersFromFile()
	if err != nil {
		log.Println(err)
	}
	return result
}

type UserRoles struct {
	UserId string   `json:"user" yaml:"user"`
	Roles  []string `json:"roles" yaml:"roles"`
}
type UserDictionary struct {
	Users []UserRoles `json:"users" yaml:"users"`
}

func (a *Auth) LoadUsersFromFile() error {
	var dict UserDictionary
	data, err := ioutil.ReadFile(a.filename)
	if err != nil {
		return err
	}
	if strings.HasSuffix(a.filename, "json") {
		err = json.Unmarshal(data, &dict)
	} else {
		err = yaml.Unmarshal(data, &dict)
	}
	if err != nil {
		return err
	}
	for _, user := range dict.Users {
		a.AddUser(user.UserId, a.getRoles(user.Roles)...)
	}
	return nil
}

func (a *Auth) getRoles(roles []string) []Role {
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
func (a *Auth) AddUser(userId string, roles ...Role) {
	a.users.AddUser(userId, roles...)
}

func (a Auth) getUserId(claims jwt.MapClaims) string {
	userId := claims["email"]
	if userId != nil {
		return userId.(string)
	}
	return ""
}

func (a Auth) claimsHasRole(claims jwt.MapClaims, r Role) bool {
	userId := a.getUserId(claims)
	return a.users.HasRole(userId, r)
}

func (a Auth) DefaultJwtClaimHandler(claims jwt.MapClaims, r *http.Request, w http.ResponseWriter) error {
	switch r.Method {
	case "GET", "OPTIONS":
		return nil
	case "POST", "DELETE", "PUT":
		if !a.claimsHasRole(claims, Editor) {
			return throwUnauthorizedException(*r, w)
		}
		return nil
	default:
		return throwUnauthorizedException(*r, w)
	}
}

func throwUnauthorizedException(r http.Request, w http.ResponseWriter) error {
	err := errors.New(fmt.Sprintf("Unauthorized request %s %s", r.Method, r.RequestURI))
	http.Error(w, err.Error(), http.StatusUnauthorized)
	return err
}
