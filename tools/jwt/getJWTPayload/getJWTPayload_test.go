package getJWTPayload

import (
	"testing"
)

func TestGetJWTPayload(t *testing.T) {
	JWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzM2Nzk0MjcsImlhdCI6MTczMzU5MzAyNywiaXNzIjoibXktc2VydmljZSIsInJvbGUiOiJhZG1pbiIsInN1YiI6MX0.JZDqNtkOHmMkzWZDA6nHD50TrY1e0SXVzE0aarFUucw"
	userId := int64(1)
	payload := map[string]any{
		"role": "admin",
	}
	signKey := "secret-key"
	issuerService := "my-service"

	parsedPayload, err := GetJWTPayload(JWT, signKey)

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
