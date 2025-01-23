package main

import (
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestKeyCloakLogin(t *testing.T) {
	err := godotenv.Load()
	require.NoError(t, err)
	conf := Config{
		Url:      os.Getenv("KEYCLOAK_SCENARIO_URL"),
		Username: os.Getenv("KEYCLOAK_SCENARIO_USERNAME"),
		Password: os.Getenv("KEYCLOAK_SCENARIO_PASSWORD"),
		AuthType: "keycloak",
		Verbose:  true,
	}

	err = action(&conf)
	require.NoError(t, err)
	data, err := os.ReadFile("token.txt")
	require.NoError(t, err)
	assert.NotEmpty(t, string(data))
}

func TestDefaultLogin(t *testing.T) {
	err := godotenv.Load()
	require.NoError(t, err)
	conf := Config{
		Url:      os.Getenv("DEFAULT_SCENARIO_URL"),
		Username: os.Getenv("DEFAULT_SCENARIO_USERNAME"),
		Password: os.Getenv("DEFAULT_SCENARIO_PASSWORD"),
		Verbose:  true,
	}

	err = action(&conf)
	require.NoError(t, err)
	data, err := os.ReadFile("token.txt")
	require.NoError(t, err)
	assert.NotEmpty(t, string(data))

}
