package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const bindCookieName = "download_token"

func urlSignWithCookie(rawURL, secret string, expiresIn int) (string, *http.Cookie, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", nil, err
	}

	// Generate random binding value.
	bindBytes := make([]byte, 10)
	if _, err := rand.Read(bindBytes); err != nil {
		return "", nil, err
	}

	// This exact string goes into the URL.
	bind := base64.RawURLEncoding.EncodeToString(bindBytes)

	// Hash the exact value in the URL.
	hash := sha256.Sum256([]byte(bind))
	cookieValue := base64.RawURLEncoding.EncodeToString(hash[:])

	expires := time.Now().Unix() + int64(expiresIn)

	params := url.Values{}
	params.Set("expires", strconv.FormatInt(expires, 10))
	params.Set("bind", bind)

	// Sign exactly: path + "?" + sorted query.
	sortedQuery := params.Encode()
	toSign := u.Path + "?" + sortedQuery

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(toSign))

	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// Add signature.
	params.Set("signature", signature)
	u.RawQuery = params.Encode()

	cookie := &http.Cookie{
		Name:     bindCookieName,
		Value:    cookieValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	return u.String(), cookie, nil
}

func main() {
	secret := "secret-key"
	path := "/downloads/forbidden.html"

	fmt.Println("=== Cookie-bound signed URL ===")

	signedURL, cookie, err := urlSignWithCookie(
		"http://localhost:8080"+path,
		secret,
		3600,
	)
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
