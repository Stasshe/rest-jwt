// Stage 2: 攻撃者が送ってきた"alg"ヘッダを信用し、alg=noneのときは
// 署名検証を丸ごとスキップしてしまうJWT認証。
// 実行: go run ./cmd/stage2-jwt-alg-none — docs/05_attack_alg_none.md 参照
package main

import (
	"log"
	"net/http"

	"rest-jwt/internal/authserver"
	"rest-jwt/internal/hmaccodec"
)

func main() {
	codec := hmaccodec.Codec{
		Secret:       []byte("s0m3-r4nd0m-s3rv3r-secret!"),
		AllowAlgNone: true, // <- ここがバグ
	}
	log.Println("stage2-jwt-alg-none listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", authserver.New(codec)))
}
