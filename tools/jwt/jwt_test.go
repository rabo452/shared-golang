package jwthelper

import "testing"

// positive case
func TestValidateJWT(t *testing.T) {
	helper := JWTHelper{}
	JWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzM2Nzk0MjcsImlhdCI6MTczMzU5MzAyNywiaXNzIjoibXktc2VydmljZSIsInJvbGUiOiJhZG1pbiIsInN1YiI6MX0.JZDqNtkOHmMkzWZDA6nHD50TrY1e0SXVzE0aarFUucw"
	signKey := "secret-key"

	isValidJWT := helper.IsJWTValid(signKey, JWT)

	if !isValidJWT {
		t.Error("JWT is not valid")
	}

	JWT += "some-unknown-value"
}

// fail case
func TestValidateJWTFailure(t *testing.T) {
	helper := JWTHelper{}
	JWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzM2Nzk0MjcsImlhdCI6MTczMzU5MzAyNywiaXNzIjoibXktc2VydmljZSIsInJvbGUiOiJhZG1pbiIsInN1YiI6MX0.JZDqNtkOHmMkzWZDA6nHD50TrY1e0SXVzE0aarFUucw"
	JWT += "some additional value"
	signKey := "secret-key"

	isValidJWT := helper.IsJWTValid(signKey, JWT)

	if isValidJWT {
		t.Error("JWT should be invalid, but it doesn't")
	}
}

// test whether the payload is correctly taken
func TestGetJWTPayload(t *testing.T) {
	helper := JWTHelper{}
	JWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzM2Nzk0MjcsImlhdCI6MTczMzU5MzAyNywiaXNzIjoibXktc2VydmljZSIsInJvbGUiOiJhZG1pbiIsInN1YiI6MX0.JZDqNtkOHmMkzWZDA6nHD50TrY1e0SXVzE0aarFUucw"
	userId := int64(1)
	payload := map[string]any{
		"role": "admin",
	}
	signKey := "secret-key"
	issuerService := "my-service"

	parsedPayload, err := helper.GetJWTPayload(JWT, signKey)

	if err != nil {
		t.Errorf("Cannot fetch JWT payload due to error: %s", err.Error())
	}

	if sub, ok := parsedPayload["sub"].(int64); (ok && int64(sub) != userId) || parsedPayload["iss"] != issuerService || parsedPayload["exp"] == nil || parsedPayload["iat"] == nil {
		t.Errorf("The values of the JWT is modified/absent/violated, the parsed payload: %v", parsedPayload)
	}

	for key, val := range payload {
		if parsedPayload[key] != val {
			t.Errorf("The values of the JWT is modified/absent/violated, the parsed payload: %v", parsedPayload)
		}
	}
}

// check whatever the jwt payload persists
func TestJWTPayload(t *testing.T) {
	helper := JWTHelper{}
	userId := "some-user-id-hash"
	payload := map[string]any{
		"role": "admin",
	}
	signKey := "secret-key"
	issuerService := "my-service"

	_, err := helper.GenerateJWT(signKey, issuerService, userId, payload)

	if err != nil {
		t.Errorf("unable to create JWT due to error: %s", err.Error())
	}
}
