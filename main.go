package main

import (
	"fmt"
	"log"
	"os"

	keycloak "github.com/cybrarymin/opennebula-auth-plugin/internal/keycloak"
	"github.com/cybrarymin/opennebula-auth-plugin/internal/opennebula"
)

func main() {
	authnData, err := opennebula.FetchAuthData()
	if err != nil {
		log.Println("couldn't parse xml data provided by opennebula sunstone", err)
		os.Exit(255)
	}

	ke, err := keycloak.NewEndpoint()
	if err != nil {
		log.Println("couldn't initialize the keycloak configuration", err)
		os.Exit(255)
	}

	ok, AuthenticatedUserRes, err := ke.AuthenticateUser(authnData)

	if err != nil && !ok {
		log.Println(err)
		os.Exit(255)
	}

	ok, err = ke.ValidateTokenSignature(AuthenticatedUserRes)
	if err != nil && ok {
		log.Printf("token signature validation failed.\n Error: %s", error.Error(err))
		os.Exit(255)
	}
	// returning opennebula understable format of authentication successfull
	fmt.Printf("%s %s %s", "keycloak", authnData.Username, authnData.Secret)

}
