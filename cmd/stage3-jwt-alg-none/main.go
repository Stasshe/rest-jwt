// Stage 3: JWT認証。攻撃者が送ってきた"alg"ヘッダを信用し、alg=noneの
// ときは署名検証を丸ごとスキップしてしまうバグを含む。
// このファイル単体で完結している(上から下に読めば全部わかる)。
// 実行: go run ./cmd/stage3-jwt-alg-none — docs/04_jwt_alg_none.md 参照
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

// secretはこのサーバだけが知っているはずの署名鍵。
var secret = []byte("s0m3-r4nd0m-s3rv3r-secret!")

// claimsはトークンの中身(payload)。
type claims struct {
	Subject   string `json:"sub"`
	Role      string `json:"role"`
	ExpiresAt int64  `json:"exp"`
}

func b64(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

// issueToken は常に正しくHS256で署名する。壊れているのはVerify側だけ、
// というのが実際のJWTライブラリでも多いバグの起き方。
func issueToken(sub, role string) string {
	c := claims{Subject: sub, Role: role, ExpiresAt: time.Now().Add(15 * time.Minute).Unix()}
	signingInput := b64(map[string]string{"alg": "HS256", "typ": "JWT"}) + "." + b64(c)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig
}

// verifyToken がこのstageの本体。header.alg を信用して分岐している
// のがバグの根っこ — alg:"none" なら署名を一切見ずに通してしまう。
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

	switch header.Alg {
	case "HS256":
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(parts[0] + "." + parts[1]))
		want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(want), []byte(parts[2])) {
			return claims{}, errors.New("signature mismatch")
		}
	case "none":
		// バグ: alg=noneのときは検証すべきものが無い、として
		// 署名部分(parts[2])を完全に無視している。
	default:
		return claims{}, errors.New("unsupported alg")
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

// handleAdmin はDBを引かず、トークンのroleクレームだけで認可する。
// 検証(verifyToken)が壊れれば、この判定も同時に壊れる。
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

	log.Println("stage3-jwt-alg-none listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
