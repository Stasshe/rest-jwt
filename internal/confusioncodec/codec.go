// Package confusioncodec issues RS256 tokens but its verifier still
// branches on the attacker-controlled "alg" header. When alg=HS256, it
// verifies the HMAC using the RSA *public* key's PEM bytes as the secret —
// the same bytes it happily publishes at GET /pubkey. Since RSA public
// keys are meant to be public, an attacker who reads them can sign their
// own HS256 tokens with them.
//
// This is the classic RS256/HS256 "algorithm confusion" bug (CVE-2016-5431
// class): the fix is never to let the token's own header choose the
// verification algorithm.
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

// New generates a fresh RSA keypair for the server process.
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
		// BUG: the "secret" is the public key's own PEM bytes — public by
		// design, so anyone who called GET /pubkey already has it.
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
