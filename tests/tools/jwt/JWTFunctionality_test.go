package jwttest

import (
	"testing"

	jwt "github.com/rabo452/shared-golang/tools/jwt"
)

// test overall JWT package functionality
func TestJWTFunctionality(t *testing.T) {
	helper := jwt.JWTHelper{}
	userId := "some-user-id-hash"
	payload := map[string]any{
		"role": "admin",
	}
	signKey := "secret-key"
	issuerService := "my-service"

	token, err := helper.GenerateJWT(signKey, issuerService, userId, payload)

	if err != nil {
		t.Errorf("unable to create JWT due to error: %s", err.Error())
	}

	isTokenValid := helper.IsJWTValid(signKey, token)

	if !isTokenValid {
		t.Errorf("token should be valid but it is not valid")
	}

	parsedPayload, err := helper.GetJWTPayload(token, signKey)

	if err != nil {
		t.Errorf("unable to parse JWT token (%s) payload due to error: %s", token, err.Error())
	}

	if parsedPayload["sub"] != userId {
		t.Errorf("JWT user id (sub field) %s != %s", parsedPayload["sub"], userId)
	}

	for key, val := range payload {
		if val != parsedPayload[key] {
			t.Errorf("JWT payload attribute is incorrect, %v should be equal to %v", parsedPayload[key], val)
		}
	}
}
