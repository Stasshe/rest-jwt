// Package confusioncodec はRS256でトークンを発行するが、検証側は
// 攻撃者が操作できる"alg"ヘッダで依然として分岐する。alg=HS256の
// ときは、RSA*公開*鍵のPEMバイト列をHMACの"秘密"鍵として使って
// しまう — その同じバイト列をGET /pubkeyで自ら公開しているのに。
// RSA公開鍵は名前の通り公開が前提なので、それを読んだ攻撃者は
// 自分でHS256署名したトークンを作れてしまう。
//
// これは実在したRS256/HS256「アルゴリズム混同」脆弱性のクラス
// (CVE-2016-5431系)。修正は「トークン自身のヘッダに検証方式を
// 選ばせない」こと、この一点に尽きる。
package confusioncodec

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
	"strings"
	"time"

	"rest-jwt/internal/authserver"
)

type Codec struct {
	private *rsa.PrivateKey
	public  *rsa.PublicKey
}

// New はサーバプロセス用に新しいRSA鍵ペアを生成する。
func New() (*Codec, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &Codec{private: key, public: &key.PublicKey}, nil
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func (c *Codec) PublicKeyPEM() []byte {
	der, _ := x509.MarshalPKIXPublicKey(c.public)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func b64(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (c *Codec) Issue(claims authserver.Claims) (string, error) {
	now := time.Now()
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = now.Add(15 * time.Minute).Unix()

	h, err := b64(header{Alg: "RS256", Typ: "JWT"})
	if err != nil {
		return "", err
	}
	p, err := b64(claims)
	if err != nil {
		return "", err
	}
	signingInput := h + "." + p
	digest := sha256.Sum256([]byte(signingInput))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, c.private, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	sig := base64.RawURLEncoding.EncodeToString(sigBytes)
	return signingInput + "." + sig, nil
}

func (c *Codec) Verify(token string) (authserver.Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return authserver.Claims{}, errors.New("malformed token")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return authserver.Claims{}, errors.New("malformed header")
	}
	var h header
	if err := json.Unmarshal(headerJSON, &h); err != nil {
		return authserver.Claims{}, errors.New("malformed header")
	}
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return authserver.Claims{}, errors.New("malformed signature")
	}

	switch h.Alg {
	case "RS256":
		digest := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(c.public, crypto.SHA256, digest[:], sig); err != nil {
			return authserver.Claims{}, errors.New("signature mismatch")
		}
	case "HS256":
		// バグ: ここでの"秘密鍵"は公開鍵自身のPEMバイト列であり、
		// 公開が前提の値。GET /pubkeyを呼んだ者は全員既に持っている。
		mac := hmac.New(sha256.New, c.PublicKeyPEM())
		mac.Write([]byte(signingInput))
		want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(want), []byte(parts[2])) {
			return authserver.Claims{}, errors.New("signature mismatch")
		}
	default:
		return authserver.Claims{}, errors.New("unsupported alg")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return authserver.Claims{}, errors.New("malformed payload")
	}
	var claims authserver.Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return authserver.Claims{}, errors.New("malformed payload")
	}
	if time.Now().Unix() > claims.ExpiresAt {
		return authserver.Claims{}, errors.New("token expired")
	}
	return claims, nil
}
