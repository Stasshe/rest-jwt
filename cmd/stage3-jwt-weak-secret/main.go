// Stage 3: stage2とほぼ同じファイル。違いは verifyToken から
// alg:none の抜け道が消えていること(検証ロジックは正しい)、その
// 代わり secret が辞書に載るほど短いこと。stage2と見比べて、
// 直った箇所と残っているバグの場所を探すとよい。
// 実行: go run ./cmd/stage3-jwt-weak-secret — docs/06_attack_weak_secret.md 参照
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"rest-jwt/internal/userstore"
)

// secret: 短くて辞書に載る値。tools/bruteforce/wordlist.txt に含まれる。
//
// 何がダメか:
//
//	HS256の署名は HMAC-SHA256(secret, header.payload) で、アルゴリズムは
//	公開されている。攻撃者に足りないのはsecretの値だけ。それが辞書に載る
//	程度だと、「候補で署名を再計算して、手元のトークンの署名と一致するか」
//	を試すだけで割れる。パスワードクラック(オフライン総当たり)と同じ構造。
//
// なぜ厄介か:
//
//   - 必要なのは正規トークン1つだけ(自分のログインで得たもの、盗聴、XSS等)。
//   - 試行はすべて攻撃者のPC上で完結する。サーバにはリクエストが1つも
//     飛ばないので、ログにもレート制限にも一切かからない。
//   - 割れた後は、正しい署名の偽トークンを何枚でも作れる。サーバ側では
//     本物と区別がつかない(検証ロジックは正しく動いている)。
//
// 直し方:
//
//	HS256の鍵長(256bit=32バイト)以上の暗号論的乱数を使う。
//	人間が覚えられる文字列は鍵にしない。ソースに直書きせずシークレット管理
//	から読む(stage5参照)。
var secret = []byte("sunny")

type claims struct {
	Subject   string `json:"sub"`
	Role      string `json:"role"`
	ExpiresAt int64  `json:"exp"`
}

func b64(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func issueToken(sub, role string) string {
	c := claims{Subject: sub, Role: role, ExpiresAt: time.Now().Add(15 * time.Minute).Unix()}
	signingInput := b64(map[string]string{"alg": "HS256", "typ": "JWT"}) + "." + b64(c)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig
}

// verifyToken: alg:noneは拒否する(stage2のバグは無い)。ただし
// secretの値そのものが弱いので、署名検証は正しくても偽造できる。
//
// stage2からの変更点は alg を HS256 に固定したことと secret の値。検証
// コードに間違いは無く、「検証コードが正しい」ことと「システムが安全」で
// あることは別、というのがこのstageの教訓。署名検証の安全性は、鍵の秘密性・
// 推測困難性が前提になる。
func verifyToken(token string) (claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims{}, errors.New("malformed token")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims{}, errors.New("malformed header")
	}
	var header struct{ Alg string }
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return claims{}, errors.New("malformed header")
	}
	if header.Alg != "HS256" {
		return claims{}, errors.New("unsupported alg")
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(parts[2])) {
		return claims{}, errors.New("signature mismatch")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims{}, errors.New("malformed payload")
	}
	var c claims
	if err := json.Unmarshal(payloadJSON, &c); err != nil {
		return claims{}, errors.New("malformed payload")
	}
	if time.Now().Unix() > c.ExpiresAt {
		return claims{}, errors.New("token expired")
	}
	return c, nil
}

// --- HTTPハンドラ ---------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func setTokenCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    token,
		Path:     "/",
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
	setTokenCookie(w, issueToken(u.Username, u.Role))
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged in"})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "access_token", Value: "", Path: "/", MaxAge: -1})
	w.WriteHeader(http.StatusOK)
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	c, ok := verifyRequest(w, r)
	if !ok {
		return
	}
	u, found := userstore.Lookup(c.Subject)
	if !found {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unknown subject"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": u.Username, "role": u.Role})
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	c, ok := verifyRequest(w, r)
	if !ok {
		return
	}
	if c.Role != "admin" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": "🚩 welcome, admin"})
}

func verifyRequest(w http.ResponseWriter, r *http.Request) (claims, bool) {
	cookie, err := r.Cookie("access_token")
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
		return claims{}, false
	}
	c, err := verifyToken(cookie.Value)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return claims{}, false
	}
	return c, true
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", handleLogin)
	mux.HandleFunc("POST /logout", handleLogout)
	mux.HandleFunc("GET /me", handleMe)
	mux.HandleFunc("GET /admin", handleAdmin)

	log.Println("stage3-jwt-weak-secret listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
