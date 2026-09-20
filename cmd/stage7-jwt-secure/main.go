// Stage 7: 修正版サーバ。ライブラリ(golang-jwt/v5)を使い、
// アルゴリズムを明示的に許可リスト化して(トークン自身の"alg"
// ヘッダを絶対に信用しない)、十分に長いランダム鍵を使い、
// 短命なアクセストークンをサーバ側のリフレッシュセッションで
// 裏打ちする。ログアウトはこのリフレッシュセッションを消すだけ
// — 素のステートレスJWTにはできない「取り消し」をここで補っている。
// 実行: go run ./cmd/stage7-jwt-secure — docs/08_jwt_defense.md 参照
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"rest-jwt/internal/userstore"
)

const (
	accessTokenTTL  = 2 * time.Minute
	refreshTokenTTL = 30 * time.Minute
)

// secretはstage3/4と違い、起動のたびに生成する32バイトの乱数
// (実運用ではシークレット管理システムからロードする)。
var secret []byte

// refreshSessions はサーバ側で握っているリフレッシュトークンの実体。
// Cookieセッション(stage6)と同じ発想 — アクセストークンは
// ステートレスなJWTに、リフレッシュだけはサーバ側の状態に戻している。
var (
	sessionsMu sync.Mutex
	sessions   = map[string]refreshSession{}
)

type refreshSession struct {
	Subject   string
	Role      string
	ExpiresAt time.Time
}

func issueAccessToken(sub, role string) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  sub,
		"role": role,
		"iat":  now.Unix(),
		"exp":  now.Add(accessTokenTTL).Unix(),
	})
	return token.SignedString(secret)
}

// verifyAccessToken がこのstageの要。WithValidMethodsでアルゴリズムを
// サーバ側に固定しており、トークンのヘッダからは一切読まない
// — stage3(none)とstage5(RS256/HS256混同)の両方への対策になる。
func verifyAccessToken(tokenStr string) (sub, role string, err error) {
	parsed, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !parsed.Valid {
		return "", "", errors.New("invalid token")
	}
	mapClaims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", errors.New("invalid claims")
	}
	sub, _ = mapClaims["sub"].(string)
	role, _ = mapClaims["role"].(string)
	if sub == "" {
		return "", "", errors.New("missing subject")
	}
	return sub, role, nil
}

func issueRefreshToken(sub, role string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	sessionsMu.Lock()
	sessions[token] = refreshSession{Subject: sub, Role: role, ExpiresAt: time.Now().Add(refreshTokenTTL)}
	sessionsMu.Unlock()
	return token, nil
}

// --- HTTPハンドラ ---------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func setCookie(w http.ResponseWriter, name, value, path string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct{ Username, Password string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	u, err := userstore.Authenticate(body.Username, body.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	access, err := issueAccessToken(u.Username, u.Role)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "issue failed"})
		return
	}
	refresh, err := issueRefreshToken(u.Username, u.Role)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "issue failed"})
		return
	}
	setCookie(w, "access_token", access, "/")
	setCookie(w, "refresh_token", refresh, "/refresh")
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged in"})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("refresh_token"); err == nil {
		sessionsMu.Lock()
		delete(sessions, c.Value)
		sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "access_token", Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: "", Path: "/refresh", MaxAge: -1})
	w.WriteHeader(http.StatusOK)
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("refresh_token")
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no refresh token"})
		return
	}

	sessionsMu.Lock()
	s, ok := sessions[c.Value]
	sessionsMu.Unlock()
	if !ok || time.Now().After(s.ExpiresAt) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "refresh rejected"})
		return
	}

	access, err := issueAccessToken(s.Subject, s.Role)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "issue failed"})
		return
	}
	setCookie(w, "access_token", access, "/")
	writeJSON(w, http.StatusOK, map[string]string{"status": "refreshed"})
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	sub, _, ok := verifyRequest(w, r)
	if !ok {
		return
	}
	u, found := userstore.Lookup(sub)
	if !found {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unknown subject"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": u.Username, "role": u.Role})
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	_, role, ok := verifyRequest(w, r)
	if !ok {
		return
	}
	if role != "admin" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": "🚩 welcome, admin"})
}

func verifyRequest(w http.ResponseWriter, r *http.Request) (sub, role string, ok bool) {
	cookie, err := r.Cookie("access_token")
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
		return "", "", false
	}
	sub, role, err = verifyAccessToken(cookie.Value)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return "", "", false
	}
	return sub, role, true
}

func main() {
	secret = make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", handleLogin)
	mux.HandleFunc("POST /logout", handleLogout)
	mux.HandleFunc("POST /refresh", handleRefresh)
	mux.HandleFunc("GET /me", handleMe)
	mux.HandleFunc("GET /admin", handleAdmin)

	log.Println("stage7-jwt-secure listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
