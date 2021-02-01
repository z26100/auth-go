package auth

import "errors"

type UserManagement struct {
	Users map[string]*UserProfile
}

func DefaultUserManagement() UserManagement {
	return UserManagement{
		Users: make(map[string]*UserProfile),
	}
}
func (u *UserManagement) Clear() {
	u.Users = make(map[string]*UserProfile)
}

func (u UserManagement) GetRolesForUser(userId string) []Role {
	if u.Users == nil {
		return nil
	}
	if u.Users[userId] == nil {
		return nil
	}
	result := make([]Role, len(u.Users[userId].Roles))
	for i, j := range u.Users[userId].Roles {
		result[i] = Role(j)
	}
	return result
}

func (u *UserManagement) AddUser(userId string, roles ...Role) error {
	p := defaultProfile()
	u.Users[userId] = &p
	return u.AssignRolesToUser(userId, roles...)
}
func (u UserManagement) GetUser(userId string) (*UserProfile, error) {
	user := u.Users[userId]
	if user == nil {
		return nil, errors.New("no user found")
	}
	return user, nil
}
func (u *UserManagement) RemoveUser(userId string) {
	delete(u.Users, userId)
}

func (u UserManagement) HasRole(userId string, role Role) bool {
	user, err := u.GetUser(userId)
	if err != nil {
		return false
	}
	return user.HasRole(role)
}

func (u *UserManagement) AssignRolesToUser(userId string, roles ...Role) error {
	user, err := u.GetUser(userId)
	if err != nil {
		return err
	}
	for _, role := range roles {
		user.AddRole(role)
	}
	return nil
}
func (u *UserManagement) RemoveRolesFromUser(userId string, roles ...Role) error {
	user, err := u.GetUser(userId)
	if err != nil {
		return err
	}
	for _, role := range roles {
		user.RemoveRole(role)
	}
	return nil
}
