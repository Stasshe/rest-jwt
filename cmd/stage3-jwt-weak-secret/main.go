// Stage 3: 検証ロジック自体は正しい(alg=noneは拒否される)が、
// HMAC鍵が辞書攻撃で見つかる強度しかない。
// 実行: go run ./cmd/stage3-jwt-weak-secret — docs/06_attack_weak_secret.md 参照
package main

import (
	"log"
	"net/http"

	"rest-jwt/internal/authserver"
	"rest-jwt/internal/hmaccodec"
)

func main() {
	codec := hmaccodec.Codec{
		Secret:       []byte("sunny"), // <- ここがバグ: 推測可能。tools/bruteforce/wordlist.txt に含まれる
		AllowAlgNone: false,
	}
	log.Println("stage3-jwt-weak-secret listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", authserver.New(codec)))
}
