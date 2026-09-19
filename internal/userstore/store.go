// Package userstore is an in-memory user database shared by every stage.
// It intentionally has no "admin" account: the /admin endpoint in the JWT
// stages authorizes purely on the role claim inside the token, never by
// looking up an admin row. That is the point of the exercises — a forged
// claim is enough if verification is broken.
package userstore

import "errors"

// User is a minimal account record.
type User struct {
	Username string
	Password string
	Role     string
}

var users = map[string]User{
	"alice": {Username: "alice", Password: "password123", Role: "user"},
	"bob":   {Username: "bob", Password: "hunter2", Role: "user"},
}

// ErrInvalidCredentials is returned when username/password don't match.
var ErrInvalidCredentials = errors.New("invalid username or password")

// Authenticate checks a username/password pair and returns the account.
func Authenticate(username, password string) (User, error) {
	u, ok := users[username]
	if !ok || u.Password != password {
		return User{}, ErrInvalidCredentials
	}
	return u, nil
}

// Lookup returns an account by username, for handlers that need the
// profile behind a verified token subject.
func Lookup(username string) (User, bool) {
	u, ok := users[username]
	return u, ok
}
