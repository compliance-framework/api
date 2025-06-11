package main

import (
	"os"

	"github.com/compliance-framework/configuration-service/cmd"
)

// Swagger documentation
//
//	@title									Continuous Compliance Framework API
//	@version								1
//	@description							This is the API for the Continuous Compliance Framework.
//	@host									localhost:8080
//	@accept									json
//	@produce								json
//	@BasePath								/api
//	@externalDocs.description				OpenAPI
//	@externalDocs.url						https://swagger.io/resources/open-api/
//	@securitydefinitions.oauth2.password	OAuth2Password
//	@tokenUrl								/api/auth/token
func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
