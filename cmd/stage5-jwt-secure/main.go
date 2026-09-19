// Stage 5: 修正版サーバ。実行: go run ./cmd/stage5-jwt-secure
// stage2/3/4の攻撃をこのサーバに試して、通らないことを確認する。
// docs/08_defense.md 参照
package main

import (
	"crypto/rand"
	"log"
	"net/http"

	"rest-jwt/internal/authserver"
	"rest-jwt/internal/securecodec"
)

func main() {
	secret := make([]byte, 32) // 実運用では起動のたびに生成せず、シークレット管理システムからロードする
	if _, err := rand.Read(secret); err != nil {
		log.Fatal(err)
	}
	codec := securecodec.New(secret)

	log.Println("stage5-jwt-secure listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", authserver.New(codec)))
}
