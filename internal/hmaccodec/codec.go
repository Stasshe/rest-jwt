// Package hmaccodec はライブラリを使わない手実装のJWT codec。
// ワイヤーフォーマットそのもの(header.payload.signature、各部を
// base64urlエンコードしてドットで繋ぐ)を理解させるために使う。
//
// 設定で切り替えられるバグを1つ持ち、それを2つのstageで使い回す。
//
//   - AllowAlgNone: 攻撃者が操作できる"alg"ヘッダを信用し、
//     "none"のときは署名検証を丸ごとスキップする。
//     2015年前後に実際に見つかったalg:none脆弱性のクラス。
//   - 短いSecret: 検証ロジック自体は正しいが、HMAC鍵が
//     ブルートフォース/辞書攻撃で見つかる強度しかない。
//
// Issueは常にHS256で正しく署名する。壊れうるのはVerifyだけ
// — 実際のバグも「甘すぎる発行者」ではなく「甘すぎる検証者」で
// 起きることが多いのを反映している。
package hmaccodec

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"rest-jwt/internal/authserver"
)

type Codec struct {
	Secret       []byte
	AllowAlgNone bool // stage2: 検証側のバグ
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func b64(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (c Codec) Issue(claims authserver.Claims) (string, error) {
	now := time.Now()
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = now.Add(15 * time.Minute).Unix()

	h, err := b64(header{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", err
	}
	p, err := b64(claims)
	if err != nil {
		return "", err
	}
	signingInput := h + "." + p
	mac := hmac.New(sha256.New, c.Secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig, nil
}

func (c Codec) Verify(token string) (authserver.Claims, error) {
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

	switch h.Alg {
	case "HS256":
		mac := hmac.New(sha256.New, c.Secret)
		mac.Write([]byte(parts[0] + "." + parts[1]))
		want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(want), []byte(parts[2])) {
			return authserver.Claims{}, errors.New("signature mismatch")
		}
	case "none":
		if !c.AllowAlgNone {
			return authserver.Claims{}, errors.New(`alg "none" rejected`)
		}
		// バグ: alg=noneは「検証すべきものが何もない」という意味になり、
		// トークンの署名部分は完全に無視される。
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
