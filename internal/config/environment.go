// This package defines environment configuration
// for Cookie settings
package config

type EnvironmentType string

const (
	EnvironmentProduction  EnvironmentType = "production"
	EnvironmentLocal       EnvironmentType = "local"
	EnvironmentDevelopment EnvironmentType = "development"
	EnvironmentEmpty       EnvironmentType = ""
)
