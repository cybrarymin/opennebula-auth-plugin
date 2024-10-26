package tools

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

func JWKsCreator() (jwk.Key, error) {
	// Generate RSA key
	privateKey, err := LoadPrivateKey()
	if err != nil {
		log.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	jwkKey, err := jwk.New(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create symmetric key: %s\n", err)
	}

	kid := "_k8FaERkHFDiCeGFigFrXh9eB9_XkinodK9QK6hsG9k"
	jwkKey.Set(jwk.KeyIDKey, kid)            // Key ID
	jwkKey.Set(jwk.KeyTypeKey, "RSA")        // Key type
	jwkKey.Set(jwk.AlgorithmKey, "RSA-OAEP") // Algorithm
	jwkKey.Set(jwk.KeyUsageKey, "sig")       // Key use
	n := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01}) // "AQAB" in Base64 URL encoding
	jwkKey.Set("n", n)
	jwkKey.Set("e", e)

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), // Unique serial number
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // Valid for one year
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to create self-signed certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certBase64 := base64.StdEncoding.EncodeToString(certPEM)
	jwkKey.Set("x5c", []string{certBase64})
	sha1Hash := sha1.Sum(certDER)
	jwkKey.Set("x5t", base64.RawURLEncoding.EncodeToString(sha1Hash[:]))
	sha256Hash := sha256.Sum256(certDER)
	jwkKey.Set("x5t#S256", base64.RawURLEncoding.EncodeToString(sha256Hash[:]))

	return jwkKey, nil
}

// MockJwksServer creates a mock server to serve the JWKs JSON response
func MockJwksServer(key []byte) *httptest.Server {
	handler := http.NewServeMux()
	handler.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(key)
	})
	return httptest.NewServer(handler)
}

// LoadPrivateKey loads an RSA private key from a PEM file
func LoadPrivateKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// CreateJwtToken generates a JWT token for testing
func CreateJwtToken(kid string, exp time.Time, privateKey *rsa.PrivateKey) (string, error) {
	claims := jwt.MapClaims{
		"exp": exp.Unix(),
		"sub": "testuser",
		"aud": "example_aud",
		"iss": "example_issuer",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	token.Header["typ"] = "JWT"

	return token.SignedString(privateKey)
}

// TestJwtParser tests the JwtParser function with a valid and invalid JWT
func TestJwtParser(t *testing.T) {
	key, err := JWKsCreator()
	if err != nil {
		t.Fatalf("failed to marshal key into JSON: %s\n", err)
	}
	newMap := make(map[string]interface{})
	newMap["keys"] = []jwk.Key{key}
	buf, err := json.Marshal(newMap)
	if err != nil {
		t.Fatalf("failed to marshal key into JSON: %s\n", err)
	}
	// Start the mock JWKs server
	mockServer := MockJwksServer(buf)
	defer mockServer.Close()

	// Load the private key to sign the token
	privateKey, err := LoadPrivateKey()
	if err != nil {
		t.Fatalf("Failed to load private key: %v", err)
	}

	// Generate a valid JWT with a 1-hour expiration
	validTokenString, err := CreateJwtToken(key.KeyID(), time.Now().Add(1*time.Hour), privateKey)
	if err != nil {
		t.Fatalf("Failed to create JWT: %v", err)
	}

	// Generate an expired JWT (expired 1 hour ago)
	expiredTokenString, err := CreateJwtToken(key.KeyID(), time.Now().Add(-1*time.Hour), privateKey)
	if err != nil {
		t.Fatalf("Failed to create expired JWT: %v", err)
	}

	// Define test cases
	tests := []struct {
		name        string
		tokenString string
		expectError bool
	}{
		{
			name:        "Valid JWT Token",
			tokenString: validTokenString,
			expectError: false,
		},
		{
			name:        "Expired JWT Token",
			tokenString: expiredTokenString,
			expectError: true,
		},
	}

	// //Run each test case
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Call the JwtParser function
			token, err := JwtParser(tc.tokenString, mockServer.URL+"/.well-known/jwks.json")

			// Check the expected outcome
			if tc.expectError {
				assert.Error(t, err, "Expected an error but got none")
				assert.Nil(t, token, "Expected token to be nil on error")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
				assert.NotNil(t, token, "Expected token but got nil")
				assert.Equal(t, "testuser", token.Claims.(jwt.MapClaims)["sub"], "Expected subject to be 'testuser'")
			}
		})
	}
}
