// package jwt provides tools to generate/validate JWT
package getJWTPayload

import (
	"errors"

	"github.com/golang-jwt/jwt/v4"
)

// GetJWTPayload extracts the payload from the JWT token and returns it as a map[string]any.
func GetJWTPayload(jwtToken string, JWT_SIGN_KEY string) (map[string]any, error) {
	// Parse the JWT token and verify its signature
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is HMAC (HS256)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		// Return the key used to sign the token
		return []byte(JWT_SIGN_KEY), nil
	})

	// Check for errors in parsing or invalid token
	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Extract the claims as a map[string]any
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("failed to parse claims")
	}

	// Return the claims as a map
	return claims, nil
}
