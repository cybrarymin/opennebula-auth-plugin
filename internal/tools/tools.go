package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

// Parsing the urls to extract the url path
func UrlParser(rawURL string) string {
	pUrl, _ := url.Parse(rawURL)
	return pUrl.Path
}

// Read raw http response and return them as string
func ReadHTTPResponse(httpRes *http.Response) (string, error) {
	defer httpRes.Body.Close()

	body, err := io.ReadAll(httpRes.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// json input decoder
func FromJson(httpRes *http.Response, input interface{}) error {
	if err := json.NewDecoder(httpRes.Body).Decode(input); err != nil {
		return err
	}
	return nil
}

func JwtParser(tokenString string, jwks_uri string) (*jwt.Token, error) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create the keyfunc options. Use an error handler that logs. Refresh the JWKS when a JWT signed by an unknown KID
	// is found or at the specified interval. Rate limit these refreshes. Timeout the initial JWKS refresh request after
	// 10 seconds. This timeout is also used to create the initial context.Context for keyfunc.Get.
	options := keyfunc.Options{
		Ctx: ctx,
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.Keyfunc\nError: %s", err.Error())
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	}

	// Create the JWKS from the resource at the given URL.
	jwks, err := keyfunc.Get(jwks_uri, options)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS from resource at the given URL.\nError: %s", err.Error())
	}

	// Parse the JWT.
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, jwks.Keyfunc, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the JWT.\nError: %s", err.Error())
	}

	// Check if the token is valid.
	if !token.Valid {
		return nil, fmt.Errorf("the token is not valid")
	}

	// This will be ineffectual because the line above this canceled the parent context.Context.
	// This method call is idempotent similar to context.CancelFunc.
	jwks.EndBackground()

	// do something with decoded claims
	for key, val := range claims {
		fmt.Printf("Key: %v, value: %v\n", key, val)
	}
	return token, nil
}
