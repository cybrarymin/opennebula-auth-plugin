package keyclaok

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/cybrarymin/opennebula-auth-plugin/internal/opennebula"
	"github.com/cybrarymin/opennebula-auth-plugin/internal/tools"
	"gopkg.in/yaml.v2"
)

// KeyCloakEndpoint Configuration
type KeyCloakEndpoint struct {
	KeyCloak struct {
		SrvAddr               string   `yaml:"server_addr"`
		SrvPort               int      `yaml:"server_port"`
		SrvCertPaths          []string `yaml:"server_trustbundle_crt"`
		ConfigurationEndpoint string   `yaml:"config_endpoint"`
		AuthorizationEndpoint string   `yaml:"-"`
		UserInfoEndpoint      string   `yaml:"-"`
		TokenEndpoint         string   `yaml:"-"`
		JwksURI               string   `yaml:"-"`
		EndSessionEndpoint    string   `yaml:"-"`
		Client                struct {
			ClientID     string `yaml:"client_id"`
			ClientSecret string `yaml:"client_secret"`
			GrantType    string `yaml:"grant_type"`
		} `yaml:"client"`
	} `yaml:"keycloak"`
}

// Keycloak Response for Authenticated Users
type KeyCloakAuthenticatedUser struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

// Initializing new KeyCloakEndpoint by fetching data from KeyCloak openid-configuration
func NewEndpoint() (*KeyCloakEndpoint, error) {
	var kEndpoint KeyCloakEndpoint
	opennebulaBaseDir := os.Getenv("ONE_LOCATION")
	if opennebulaBaseDir == "" {
		opennebulaBaseDir = "/etc/one/"
	}
	cfgfile, err := os.Open(opennebulaBaseDir + "auth/keycloak_auth.conf")
	if err != nil {
		return nil, err
	}
	defer cfgfile.Close()
	ymlDec := yaml.NewDecoder(cfgfile)
	err = ymlDec.Decode(&kEndpoint)
	if err != nil {
		return nil, err
	}
	if err := kEndpoint.FetchConfigData(); err != nil {
		return nil, err
	}
	return &kEndpoint, nil
}

// Addding trusted Keycloak servers certificate bundles
func (ke *KeyCloakEndpoint) FetchConfigData() error {

	tr, err := addTrustedCertificates(ke.KeyCloak.SrvCertPaths)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s:%d/%s", ke.KeyCloak.SrvAddr, ke.KeyCloak.SrvPort, ke.KeyCloak.ConfigurationEndpoint), nil)
	if err != nil {
		return err
	}

	clientReq := &http.Client{Transport: tr}
	httpRes, err := clientReq.Do(httpReq)
	if err != nil {
		return err
	}
	if httpRes.StatusCode != http.StatusOK {
		errRes, err := tools.ReadHTTPResponse(httpRes)
		if err != nil {
			return err
		}
		return errors.New(errRes)
	}

	var resData struct {
		UserInfoEndpoint      string `json:"userinfo_endpoint"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		JwksURI               string `json:"jwks_uri"`
		EndSessionEndpoint    string `json:"end_session_endpoint"`
	}
	err = tools.FromJson(httpRes, &resData)
	if err != nil {
		return err
	}

	ke.KeyCloak.TokenEndpoint = tools.UrlParser(resData.TokenEndpoint)
	ke.KeyCloak.AuthorizationEndpoint = tools.UrlParser(resData.AuthorizationEndpoint)
	ke.KeyCloak.UserInfoEndpoint = tools.UrlParser(resData.UserInfoEndpoint)
	ke.KeyCloak.JwksURI = tools.UrlParser(resData.JwksURI)
	ke.KeyCloak.EndSessionEndpoint = tools.UrlParser(resData.EndSessionEndpoint)

	return nil

}

func (ke *KeyCloakEndpoint) AuthenticateUser(authnData *opennebula.AuthData) (bool, *KeyCloakAuthenticatedUser, error) {
	var nUser KeyCloakAuthenticatedUser

	tr, err := addTrustedCertificates(ke.KeyCloak.SrvCertPaths)
	if err != nil {
		return false, nil, err
	}

	data := url.Values{}
	data.Set("client_id", ke.KeyCloak.Client.ClientID)
	data.Set("client_secret", ke.KeyCloak.Client.ClientSecret)
	data.Set("grant_type", ke.KeyCloak.Client.GrantType)
	data.Set("username", authnData.Username)
	data.Set("password", authnData.Secret)

	nhttpReq, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s:%d/%s", ke.KeyCloak.SrvAddr, ke.KeyCloak.SrvPort, ke.KeyCloak.TokenEndpoint), bytes.NewBufferString(data.Encode()))
	nhttpReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return false, nil, err
	}

	clientReq := &http.Client{Transport: tr}
	httpRes, err := clientReq.Do(nhttpReq)
	if err != nil {
		return false, nil, err
	}
	if httpRes.StatusCode != http.StatusOK {
		errRes, err := tools.ReadHTTPResponse(httpRes)
		if err != nil {
			return false, nil, err
		}
		return false, nil, errors.New(errRes)
	}

	err = tools.FromJson(httpRes, &nUser)
	if err != nil {
		return false, nil, err
	}
	return true, &nUser, nil
}

func addTrustedCertificates(certPaths []string) (*http.Transport, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		log.Println("error loading the default trusted rootCA certificates")
		return nil, err
	}

	for _, value := range certPaths {
		pemBytes, err := os.ReadFile(value)
		if err != nil {
			return nil, err
		}
		if !rootCAs.AppendCertsFromPEM(pemBytes) {
			log.Println("error adding trusted certificate files to root trusted certificate arrays")
		}
	}
	config := &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}
	return &http.Transport{TLSClientConfig: config}, nil
}

func (ke *KeyCloakEndpoint) ValidateTokenSignature(ku *KeyCloakAuthenticatedUser) (bool, error) {
	_, err := tools.JwtParser(ku.AccessToken, ke.KeyCloak.JwksURI)
	if err != nil {
		return false, err
	}
	return true, nil
}
