// package jwt provides tools to generate/validate JWT
package generateJWT

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// generates signed JWT string for the specified user
func GenerateJWT(
	JWT_SIGN_KEY string, issuerService string,
	userId int64, payload map[string]any) (string, error) {
	claims := jwt.MapClaims{
		"sub": userId,
		"iat": time.Now().UTC().Unix(),
		"exp": time.Now().UTC().Add(time.Hour * 24).Unix(),
		"iss": issuerService,
	}

	for key, val := range payload {
		claims[key] = val
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	signedToken, err := token.SignedString([]byte(JWT_SIGN_KEY))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}
