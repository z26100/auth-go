package auth

import "errors"

type UserManagement struct {
	users map[string]*UserProfile
}

func DefaultUsermanagement() UserManagement {
	return UserManagement{
		users: make(map[string]*UserProfile),
	}
}

func (u UserManagement) GetRolesForUser(userId string) map[Role]*Role {
	return u.users[userId].roles
}

func (u *UserManagement) AddUser(userId string, roles ...Role) {
	p := defaultProfile()
	u.users[userId] = &p
	_ = u.AssignRolesToUser(userId, roles...)
}
func (u UserManagement) GetUser(userId string) (*UserProfile, error) {
	user := u.users[userId]
	if user == nil {
		return nil, errors.New("no user found")
	}
	return user, nil
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
		user.roles[role] = &role
	}
	return nil
}
func (u *UserManagement) removeRolesFromUser(userId string, roles ...Role) error {
	user, err := u.GetUser(userId)
	if err != nil {
		return err
	}
	for _, role := range roles {
		delete(user.roles, role)
	}
	return nil
}
