package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	bindCookieName = "download_token"
	bindParamName  = "bind"
)

func generateSignedUrl(rawURL, secret string, expiresIn int, bindCookie *http.Cookie) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	// Hash the cookie value before including it in the URL.
	hash := sha256.Sum256([]byte(bindCookie.Value))
	cookieHash := base64.RawURLEncoding.EncodeToString(hash[:])

	// Set an expiration time
	expires := time.Now().Unix() + int64(expiresIn)

	params := url.Values{}
	params.Set("expires", strconv.FormatInt(expires, 10))
	params.Set("bind", cookieHash)

	// Sign exactly: path + "?" + sorted query.
	sortedQuery := params.Encode()
	toSign := u.Path + "?" + sortedQuery

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(toSign))

	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// Add signature.
	params.Set("signature", signature)
	u.RawQuery = params.Encode()

	return u.String(), nil
}

func main() {
	secret := "secret-key"
	path := "/downloads/forbidden.html"

	fmt.Println("=== Cookie-bound signed URL ===")

	// create the cookie with a random value
	cookie := &http.Cookie{
		Name:     bindCookieName,
		Value:    "random-value", // In a real application, this should be a securely generated random value.
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	signedURL, err := generateSignedUrl("http://localhost:8080"+path, secret, 3600, cookie)
	if err != nil {
		panic(err)
	}

	fmt.Println("Signed URL:", signedURL)
	fmt.Printf("Cookie: %s=%s\n", cookie.Name, cookie.Value)

	client := &http.Client{}

	req, err := http.NewRequest(http.MethodGet, signedURL, nil)
	if err != nil {
		panic(err)
	}

	req.AddCookie(cookie)

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	fmt.Println("Status:", resp.Status)
	fmt.Println("Response Body:")
	fmt.Println(string(body))
}
