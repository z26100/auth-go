package auth

type Role string

const (
	Anonymous Role = "anonymous"
	Viewer    Role = "viewer"
	Editor    Role = "editor"
	Admin     Role = "admin"
)

type UserProfile struct {
	roles map[Role]*Role
}

func (u UserProfile) HasRole(r Role) bool {
	return u.roles[r] != nil
}

func (u *UserProfile) AddRole(r Role) *Role {
	role := &r
	u.roles[r] = role
	return role
}
func (u *UserProfile) RemoveRole(r Role) {
	delete(u.roles, r)
}

func defaultProfile() UserProfile {
	p := UserProfile{
		roles: make(map[Role]*Role),
	}
	p.AddRole(Anonymous)
	return p
}

func PRole(r Role) *Role {
	return &r
}
