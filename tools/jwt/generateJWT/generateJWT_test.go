package generateJWT

import (
	"testing"
)

// check whatever the jwt payload persists
func TestJWTPayload(t *testing.T) {
	userId := 1
	payload := map[string]any{
		"role": "admin",
	}
	signKey := "secret-key"
	issuerService := "my-service"

	_, err := GenerateJWT(signKey, issuerService, int64(userId), payload)

	if err != nil {
		t.Errorf("unable to create JWT due to error: %s", err.Error())
	}
}
