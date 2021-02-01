package auth

import (
	"sort"
)

type Role string

const (
	Anonymous Role = "anonymous"
	Viewer    Role = "viewer"
	Editor    Role = "editor"
	Admin     Role = "admin"
)

type UserProfile struct {
	Roles []string
}

func (u UserProfile) HasRole(r Role) bool {
	i := sort.SearchStrings(u.Roles, string(r))
	return i < len(u.Roles) && u.Roles[i] == string(r)
}

func (u *UserProfile) AddRole(r Role) *Role {
	i := sort.SearchStrings(u.Roles, string(r))
	switch i {
	case 0:
		u.Roles = append([]string{string(r)}, u.Roles...)
	default:
		u.Roles = append(append(u.Roles[:i-1], string(r)), u.Roles[i:]...)
	}
	return &r
}
func (u *UserProfile) RemoveRole(r Role) {
	i := sort.SearchStrings(u.Roles, string(r))
	switch i {
	case 0:
		u.Roles = u.Roles[1:]
	case len(u.Roles):
		u.Roles = append(u.Roles[:i-1], u.Roles[i+1])
	default:
		u.Roles = u.Roles[0 : len(u.Roles)-1]
	}
}

func defaultProfile() UserProfile {
	p := UserProfile{
		Roles: make([]string, 0),
	}
	p.AddRole(Anonymous)
	return p
}

func PRole(r Role) *Role {
	return &r
}
