package auth

import (
	"encoding/json"
	"github.com/mikespook/gorbac"
	log "github.com/z26100/log-go"
	"gopkg.in/yaml.v3"
	"os"
	"regexp"
	"strings"
)

type FileType string

const (
	JSON FileType = "json"
	YAML FileType = "yaml"
	AUTO FileType = "auto"
)

var (
	rbac     = gorbac.New()
	fileType = AUTO
)

type RBACRole struct {
	*gorbac.StdRole
	Name string
}

type RBACPermission struct {
	Name string
}

func (p RBACPermission) ID() string {
	return p.Name
}
func (p RBACPermission) Match(action gorbac.Permission) bool {
	match := regexp.MustCompile(p.ID()).MatchString(action.ID())
	return match
}

func NewRole(name string) (*RBACRole, error) {
	role := &RBACRole{
		Name: name,
	}
	role.StdRole = gorbac.NewStdRole(strings.ToLower(strings.TrimSpace(name)))
	err := rbac.Add(role)
	if err != nil {
		return nil, err
	}
	return role, nil
}

func InterfaceAsString(in []interface{}) []string {
	p := make([]string, len(in))
	for i, j := range in {
		p[i] = j.(string)
	}
	return p
}
func SetParents(id string, parents []string) error {
	return rbac.SetParents(id, parents)
}

func GetRole(id string) (*RBACRole, []string, error) {
	role, parents, err := rbac.Get(id)
	if err != nil {
		return nil, nil, err
	}
	return role.(*RBACRole), parents, err
}

func AddPermission(name string) RBACPermission {
	permission := RBACPermission{
		Name: name,
	}
	return permission
}

type AssertionFunc = gorbac.AssertionFunc

func IsGranted(roleId string, p RBACPermission, fc AssertionFunc) bool {
	return rbac.IsGranted(roleId, p, fc)
}

func IsPermitted(roles []Role, action string) bool {
	p := RBACPermission{
		Name: strings.TrimSpace(strings.ToLower(action)),
	}
	for _, role := range roles {
		if IsGranted(string(role), p, nil) {
			return true
		}
	}
	return false
}

type WalkHandler func(*RBACRole, []string) error

func InherCircle() error {
	return gorbac.InherCircle(rbac)
}

func Walk(handler WalkHandler) error {
	h := func(r gorbac.Role, parents []string) error {
		return handler(r.(*RBACRole), parents)
	}
	return gorbac.Walk(rbac, h)
}

func NewRBAC() {
	rbac = gorbac.New()
}

func CloseRBAC() {
	rbac = nil
}
func SetFileType(t FileType) {
	fileType = t
}

func LoadFromFile(filename string) error {
	if fileType == AUTO {
		setAutoFileType(filename)
	}
	var data map[string]interface{}
	var err error
	switch fileType {
	case JSON:
		err = loadJson(filename, &data)
	default:
		err = loadYaml(filename, &data)
	}
	roles := data["roles"].(map[string]interface{})
	inher := data["inher"].(map[string]interface{})

	permissions := make(gorbac.Permissions)
	// Build Roles and add them to goRBAC instance
	for rid, pids := range roles {
		role, err := NewRole(rid)
		if err == nil {
			for _, pid := range pids.([]interface{}) {
				_, ok := permissions[pid.(string)]
				if !ok {
					permissions[pid.(string)] = AddPermission(pid.(string))
				}
				err = role.Assign(permissions[pid.(string)])
			}
		} else {
			log.Error(err)
		}
	}
	// Assign the inheritance relationship
	for rid, parents := range inher {
		if len(parents.([]interface{})) == 0 {
			break
		}
		if err := SetParents(rid, InterfaceAsString(parents.([]interface{}))); err != nil {
			log.Fatal(err)
		}
	}
	return err
}

func SaveAsFilename(filename string) error {
	if fileType == AUTO {
		setAutoFileType(filename)
	}

	// map[RoleId]PermissionIds
	outputRoles := make(map[string][]string)
	// map[RoleId]ParentIds
	outputInher := make(map[string][]string)

	SaveJsonHandler := func(r *RBACRole, parents []string) error {
		// WARNING: Don't use rbac instance in the handler,
		// otherwise it causes deadlock.
		permissions := make([]string, 0)
		for _, p := range r.Permissions() {
			permissions = append(permissions, p.ID())
		}
		outputRoles[r.ID()] = permissions
		outputInher[r.ID()] = parents
		return nil
	}
	if err := Walk(SaveJsonHandler); err != nil {
		return err
	}
	// Save Roles information
	data := make(map[string]interface{})
	data["roles"] = outputRoles
	data["inher"] = outputInher

	var err error
	switch fileType {
	case JSON:
		err = saveJson(filename, data)
	default:
		err = saveYaml(filename, data)
	}
	return err
}

func setAutoFileType(filename string) {
	if strings.HasSuffix(strings.ToLower(filename), ".json") {
		SetFileType(JSON)
	} else {
		SetFileType(YAML)
	}
}
func loadJson(filename string, v interface{}) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewDecoder(f).Decode(v)
}

func saveJson(filename string, v interface{}) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(v)
}

func loadYaml(filename string, v interface{}) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return yaml.NewDecoder(f).Decode(v)
}

func saveYaml(filename string, v interface{}) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	return yaml.NewEncoder(f).Encode(v)
}
