// Stage 5: サーバはRS256でトークンを発行し、GET /pubkeyで公開鍵を
// 公開する(実際のJWKSエンドポイントと同じ)。しかし検証側はトークン
// 自身の"alg"ヘッダを依然として信用しており、alg=HS256のときは
// その公開鍵のバイト列をHMAC鍵として使ってしまう — 公開鍵は
// 公開が前提の値なので、誰でも読める鍵で署名した偽トークンが通る。
// 実行: go run ./cmd/stage5-jwt-alg-confusion — docs/06_jwt_alg_confusion.md 参照
package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"rest-jwt/internal/userstore"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

type claims struct {
	Subject   string `json:"sub"`
	Role      string `json:"role"`
	ExpiresAt int64  `json:"exp"`
}

func publicKeyPEM() []byte {
	der, _ := x509.MarshalPKIXPublicKey(publicKey)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func b64(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

// issueToken は常に正しくRS256(秘密鍵)で署名する。
func issueToken(sub, role string) (string, error) {
	c := claims{Subject: sub, Role: role, ExpiresAt: time.Now().Add(15 * time.Minute).Unix()}
	signingInput := b64(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." + b64(c)

	digest := sha256.Sum256([]byte(signingInput))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	sig := base64.RawURLEncoding.EncodeToString(sigBytes)
	return signingInput + "." + sig, nil
}

// verifyToken がこのstageの本体。RS256は公開鍵で正しく検証するが、
// HS256の分岐だけ「公開鍵のPEMバイト列」をHMAC鍵として誤用している。
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
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return claims{}, errors.New("malformed signature")
	}

	switch header.Alg {
	case "RS256":
		digest := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], sig); err != nil {
			return claims{}, errors.New("signature mismatch")
		}
	case "HS256":
		// バグ: "秘密鍵"として公開鍵のPEMを使っている。この値は
		// GET /pubkeyを叩いた者なら誰でも持っている。
		mac := hmac.New(sha256.New, publicKeyPEM())
		mac.Write([]byte(signingInput))
		want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(want), []byte(parts[2])) {
			return claims{}, errors.New("signature mismatch")
		}
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

func handlePubkey(w http.ResponseWriter, r *http.Request) {
	w.Write(publicKeyPEM())
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
	token, err := issueToken(u.Username, u.Role)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "issue failed"})
		return
	}
	setTokenCookie(w, token)
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
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	privateKey = key
	publicKey = &key.PublicKey

	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", handleLogin)
	mux.HandleFunc("POST /logout", handleLogout)
	mux.HandleFunc("GET /me", handleMe)
	mux.HandleFunc("GET /admin", handleAdmin)
	mux.HandleFunc("GET /pubkey", handlePubkey)

	log.Println("stage5-jwt-alg-confusion listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
