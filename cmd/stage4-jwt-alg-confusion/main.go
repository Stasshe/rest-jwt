// Stage 4: サーバはRS256でトークンを発行し、公開鍵をGET /pubkeyで
// 公開する(実際のJWKSエンドポイントと同じ)。しかし検証側はトークン
// 自身の"alg"ヘッダを依然として信用しており、その公開鍵で署名した
// HS256トークンも受理してしまう。
// 実行: go run ./cmd/stage4-jwt-alg-confusion
// docs/07_attack_alg_confusion.md 参照
package main

import (
	"log"
	"net/http"

	"rest-jwt/internal/authserver"
	"rest-jwt/internal/confusioncodec"
)

func main() {
	codec, err := confusioncodec.New()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("stage4-jwt-alg-confusion listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", authserver.New(codec)))
}
