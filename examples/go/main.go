package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"time"
)

func main() {
	secret := "secret-key"
	path := "/downloads/forbidden.html"

	fmt.Println("Without signing, this should fail")
	fmt.Println("Unsigned URL:" + path)

	resp, err := http.Get("http://localhost:8080" + path)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	fmt.Println()
	fmt.Println("Status:", resp.Status)
	fmt.Println("Body:", string(body))
	fmt.Println()
	fmt.Println("---")
	fmt.Println("Repeat with signature and expiration")

	url := generateSignedURL(secret, path, 1*time.Hour)
	fmt.Println("Signed URL:" + url)

	resp, err = http.Get("http://localhost:8080" + url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	fmt.Println()
	fmt.Println("Status:", resp.Status)
	fmt.Println("Body:", string(body))
}

func generateSignedURL(secret, path string, ttl time.Duration) string {
	issued := time.Now().Unix()
	expires := issued + int64(ttl.Seconds())

	// Build query with sorted params
	query := url.Values{}
	query.Set("expires", fmt.Sprintf("%d", expires))

	// Sign the path with query params
	toSign := path + "?" + query.Encode()
	signature := generateSignature(toSign, secret, sha256.New)

	// Add signature to query
	query.Set("signature", signature)
	return path + "?" + query.Encode()
}

func generateSignature(input string, secret string, hashFunc func() hash.Hash) string {
	h := hmac.New(hashFunc, []byte(secret))
	h.Write([]byte(input))
	sig := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sig) // <- URL-safe Base64 without padding
}
