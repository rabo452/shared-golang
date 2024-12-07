package validateJWT

import "testing"

func TestValidateJWTSuccess(t *testing.T) {
	JWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzM2Nzk0MjcsImlhdCI6MTczMzU5MzAyNywiaXNzIjoibXktc2VydmljZSIsInJvbGUiOiJhZG1pbiIsInN1YiI6MX0.JZDqNtkOHmMkzWZDA6nHD50TrY1e0SXVzE0aarFUucw"
	signKey := "secret-key"

	isValidJWT := IsJWTValid(signKey, JWT)

	if !isValidJWT {
		t.Error("JWT is not valid")
	}
}

func TestValidateJWTFailure(t *testing.T) {
	JWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzM2Nzk0MjcsImlhdCI6MTczMzU5MzAyNywiaXNzIjoibXktc2VydmljZSIsInJvbGUiOiJhZG1pbiIsInN1YiI6MX0.JZDqNtkOHmMkzWZDA6nHD50TrY1e0SXVzE0aarFUucw"
	JWT += "some-unknown-value"
	signKey := "secret-key"

	isValidJWT := IsJWTValid(signKey, JWT)

	if isValidJWT {
		t.Error("JWT should be invalid, but it doesn't")
	}
}
