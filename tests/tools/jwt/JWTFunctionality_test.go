package jwt_test

import (
	"testing"

	"github.com/rabo452/shared-golang/tools/jwt/generateJWT"
	"github.com/rabo452/shared-golang/tools/jwt/getJWTPayload"
	"github.com/rabo452/shared-golang/tools/jwt/validateJWT"
)

func TestJWTFunctionality(t *testing.T) {
	userId := 1
	payload := map[string]any{
		"role": "admin",
	}
	signKey := "secret-key"
	issuerService := "my-service"

	token, err := generateJWT.GenerateJWT(signKey, issuerService, int64(userId), payload)

	if err != nil {
		t.Errorf("unable to create JWT due to error: %s", err.Error())
	}

	isTokenValid := validateJWT.IsJWTValid(signKey, token)

	if !isTokenValid {
		t.Errorf("token should be valid but it is not valid")
	}

	parsedPayload, err := getJWTPayload.GetJWTPayload(token, signKey)

	if err != nil {
		t.Errorf("unable to parse JWT token (%s) payload due to error: %s", token, err.Error())
	}

	for key, val := range payload {
		if val != parsedPayload[key] {
			t.Errorf("JWT payload attribute is incorrect, %v should be equal to %v", parsedPayload[key], val)
		}
	}
}
