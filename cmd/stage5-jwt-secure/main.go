// Stage 5: the fixed server. Run: go run ./cmd/stage5-jwt-secure
// Try the stage2/3/4 attacks against it — see docs/08_defense.md.
package main

import (
	"crypto/rand"
	"log"
	"net/http"

	"rest-jwt/internal/authserver"
	"rest-jwt/internal/securecodec"
)

func main() {
	secret := make([]byte, 32) // real deployments load this from a secret manager, not generate it per boot
	if _, err := rand.Read(secret); err != nil {
		log.Fatal(err)
	}
	codec := securecodec.New(secret)

	log.Println("stage5-jwt-secure listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", authserver.New(codec)))
}
