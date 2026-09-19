// Package userstore は全stage共通のインメモリユーザーDB。
// 意図的に「admin」アカウントを持たない。JWT stageの/adminは
// adminロウの検索ではなく、トークン内のroleクレームだけで認可する。
// 演習の要点はここにある — 検証が壊れれば、偽のクレーム1つで十分。
package userstore

import "errors"

// User は最小限のアカウントレコード。
type User struct {
	Username string
	Password string
	Role     string
}

var users = map[string]User{
	"alice": {Username: "alice", Password: "password123", Role: "user"},
	"bob":   {Username: "bob", Password: "hunter2", Role: "user"},
}

// ErrInvalidCredentials はusername/passwordが一致しないときに返す。
var ErrInvalidCredentials = errors.New("invalid username or password")

// Authenticate はusername/passwordの組を検証し、アカウントを返す。
func Authenticate(username, password string) (User, error) {
	u, ok := users[username]
	if !ok || u.Password != password {
		return User{}, ErrInvalidCredentials
	}
	return u, nil
}

// Lookup はusernameでアカウントを取得する。検証済みトークンのsubject
// からプロフィールを引くハンドラが使う。
func Lookup(username string) (User, bool) {
	u, ok := users[username]
	return u, ok
}
